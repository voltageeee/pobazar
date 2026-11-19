//! hush — tiny signaling relay for end-to-end encrypted rooms.
//!
//! The server only:
//!   * serves the static web client (embedded into the binary),
//!   * relays opaque encrypted binary frames between peers of a room,
//!   * hands out short-lived TURN credentials.
//!
//! It never sees room keys (they live in the URL fragment, which browsers never send),
//! nicknames, chat, or media. No logs, no analytics, no storage: rooms exist only in RAM
//! while someone is connected.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Mutex};

const INDEX: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE: &str = include_str!("../web/style.css");
const ICON: &str = include_str!("../web/icon.svg");
const ECHO_WORKLET: &str = include_str!("../web/echo-worklet.js");

const MAX_PEERS: usize = 16;
const MAX_ROOMS: usize = 5000;
/// Largest single relayed frame (encrypted file chunk / message).
const MAX_FRAME: usize = 12 * 1024 * 1024;
/// Max bytes a single connection may push per 10 s window (anti-abuse, generous).
const RATE_BYTES: usize = 64 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(70);

type Tx = mpsc::UnboundedSender<Message>;

struct Room {
    peers: HashMap<u64, Tx>,
}

struct Turn {
    secret: Vec<u8>,
    urls: Vec<String>,
    ttl: u64,
}

/// Cloudflare Realtime TURN: short-lived credentials fetched from the API and cached.
struct CfTurn {
    key_id: String,
    token: String,
    http: reqwest::Client,
    cache: Mutex<Option<(tokio::time::Instant, serde_json::Value)>>,
}

const CF_TTL: u64 = 24 * 3600; // credential lifetime
const CF_REFRESH: Duration = Duration::from_secs(3600); // hand out creds at most 1h old

impl CfTurn {
    async fn servers(&self) -> Option<serde_json::Value> {
        let mut c = self.cache.lock().await;
        if let Some((at, v)) = c.as_ref() {
            if at.elapsed() < CF_REFRESH {
                return Some(v.clone());
            }
        }
        let url = format!(
            "https://rtc.live.cloudflare.com/v1/turn/keys/{}/credentials/generate-ice-servers",
            self.key_id
        );
        let res = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "ttl": CF_TTL }))
            .send()
            .await
            .ok()?;
        if !res.status().is_success() {
            eprintln!("cf turn: http {}", res.status());
            return c.as_ref().map(|(_, v)| v.clone());
        }
        let body: serde_json::Value = res.json().await.ok()?;
        let mut list = match body.get("iceServers") {
            Some(serde_json::Value::Array(a)) => a.clone(),
            Some(o @ serde_json::Value::Object(_)) => vec![o.clone()],
            _ => return None,
        };
        // browsers time out on :53, drop it (Cloudflare's own recommendation)
        for s in list.iter_mut() {
            if let Some(serde_json::Value::Array(u)) = s.get_mut("urls") {
                u.retain(|x| x.as_str().map_or(false, |x| !x.split('?').next().unwrap_or("").ends_with(":53")));
            }
        }
        let v = serde_json::Value::Array(list);
        *c = Some((tokio::time::Instant::now(), v.clone()));
        Some(v)
    }
}

struct AppState {
    rooms: Mutex<HashMap<String, Room>>,
    stun: Vec<String>,
    turn: Option<Turn>,
    cf: Option<CfTurn>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn list(k: &str) -> Vec<String> {
    env(k)
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

#[tokio::main]
async fn main() {
    let turn = env("TURN_SECRET").map(|s| Turn {
        secret: s.into_bytes(),
        urls: list("TURN_URLS"),
        ttl: env("TURN_TTL").and_then(|v| v.parse().ok()).unwrap_or(12 * 3600),
    });
    let state = Arc::new(AppState {
        rooms: Mutex::new(HashMap::new()),
        stun: list("STUN_URLS"),
        turn,
        cf: match (env("CF_TURN_KEY_ID"), env("CF_TURN_TOKEN")) {
            (Some(key_id), Some(token)) => Some(CfTurn {
                key_id,
                token,
                http: reqwest::Client::builder().timeout(Duration::from_secs(8)).build().expect("http"),
                cache: Mutex::new(None),
            }),
            _ => None,
        },
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/r/{room}", get(index))
        .route("/app.js", get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }))
        .route("/style.css", get(|| async { asset(STYLE, "text/css; charset=utf-8") }))
        .route("/echo-worklet.js", get(|| async { asset(ECHO_WORKLET, "text/javascript; charset=utf-8") }))
        .route("/icon.svg", get(|| async { asset(ICON, "image/svg+xml") }))
        .route("/ws/{room}", get(ws_handler))
        .route(
            "/cfg",
            get(|State(st): State<Arc<AppState>>| async move {
                let mut r = serde_json::json!({ "relay": st.turn.is_some() || st.cf.is_some() }).to_string().into_response();
                r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
                security_headers(r.headers_mut());
                r
            }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .with_state(state);

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    match env("DOMAIN") {
        // Public mode: TLS with automatic Let's Encrypt certificates (TLS-ALPN-01 on :443).
        Some(domain) => {
            use rustls_acme::{caches::DirCache, AcmeConfig};
            let listen: SocketAddr = env("LISTEN").unwrap_or("[::]:443".into()).parse().expect("LISTEN");
            let cache = env("ACME_CACHE").unwrap_or("/var/lib/hush/acme".into());
            let domains: Vec<String> = domain.split(',').map(|s| s.trim().to_string()).collect();
            let mut acme = AcmeConfig::new(domains)
                .cache(DirCache::new(cache))
                .directory_lets_encrypt(env("ACME_STAGING").is_none())
                .state();
            let acceptor = acme.axum_acceptor(acme.default_rustls_config());
            tokio::spawn(async move {
                while let Some(ev) = acme.next().await {
                    if let Err(e) = ev {
                        eprintln!("acme: {e:?}");
                    }
                }
            });
            eprintln!("hush: https on {listen} for {domain}");
            let handle = axum_server::Handle::new();
            let h2 = handle.clone();
            tokio::spawn(async move {
                shutdown.await;
                h2.graceful_shutdown(Some(Duration::from_secs(3)));
            });
            axum_server::bind(listen)
                .handle(handle)
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await
                .expect("server");
        }
        // Local / behind-proxy mode: plain HTTP.
        None => {
            let listen: SocketAddr = env("LISTEN").unwrap_or("127.0.0.1:8095".into()).parse().expect("LISTEN");
            eprintln!("hush: http on {listen}");
            let l = tokio::net::TcpListener::bind(listen).await.expect("bind");
            axum::serve(l, app).with_graceful_shutdown(shutdown).await.expect("server");
        }
    }
}

fn security_headers(h: &mut HeaderMap) {
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; \
         media-src 'self' blob:; connect-src 'self'; font-src 'none'; object-src 'none'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
    set(h, "referrer-policy", "no-referrer");
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(h, "strict-transport-security", "max-age=31536000");
    set(
        h,
        "permissions-policy",
        "camera=(self), microphone=(self), display-capture=(self), fullscreen=(self), \
         geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()",
    );
    set(h, "cache-control", "no-cache");
}

fn asset(body: &'static str, ctype: &'static str) -> Response {
    let mut r = body.into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    security_headers(r.headers_mut());
    r
}

async fn index() -> Response {
    asset(INDEX, "text/html; charset=utf-8")
}

fn valid_room(r: &str) -> bool {
    (8..=64).contains(&r.len()) && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn hex(id: u64) -> String {
    format!("{id:016x}")
}

async fn ice_servers(st: &AppState) -> serde_json::Value {
    let mut out = vec![];
    if let Some(cf) = &st.cf {
        if let Some(serde_json::Value::Array(a)) = cf.servers().await {
            out.extend(a);
        }
    }
    if !st.stun.is_empty() {
        out.push(serde_json::json!({ "urls": st.stun }));
    }
    if let Some(t) = &st.turn {
        // coturn "use-auth-secret" (TURN REST API) credentials: user = expiry:random
        let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + t.ttl;
        let user = format!("{exp}:{:08x}", rand::random::<u32>());
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&t.secret).unwrap();
        mac.update(user.as_bytes());
        let cred = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        out.push(serde_json::json!({ "urls": t.urls, "username": user, "credential": cred }));
    }
    serde_json::Value::Array(out)
}

async fn ws_handler(ws: WebSocketUpgrade, Path(room): Path<String>, State(st): State<Arc<AppState>>) -> Response {
    if !valid_room(&room) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    ws.max_message_size(MAX_FRAME + 64)
        .max_frame_size(MAX_FRAME + 64)
        .on_upgrade(move |s| peer(s, room, st))
}

fn text(v: serde_json::Value) -> Message {
    Message::Text(v.to_string().into())
}

async fn peer(socket: WebSocket, room: String, st: Arc<AppState>) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let id: u64 = loop {
        let v = rand::random::<u64>();
        if v != 0 {
            break v;
        }
    };

    // ---- join
    let existing: Vec<String> = {
        let mut rooms = st.rooms.lock().await;
        if !rooms.contains_key(&room) && rooms.len() >= MAX_ROOMS {
            let _ = sink.send(text(serde_json::json!({"t":"error","e":"busy"}))).await;
            return;
        }
        let r = rooms.entry(room.clone()).or_insert_with(|| Room { peers: HashMap::new() });
        if r.peers.len() >= MAX_PEERS {
            let _ = sink.send(text(serde_json::json!({"t":"error","e":"full"}))).await;
            return;
        }
        let ex = r.peers.keys().map(|k| hex(*k)).collect();
        let join = text(serde_json::json!({"t":"join","id":hex(id)}));
        for p in r.peers.values() {
            let _ = p.send(join.clone());
        }
        r.peers.insert(id, tx.clone());
        ex
    };
    let _ = tx.send(text(serde_json::json!({
        "t": "welcome", "id": hex(id), "peers": existing, "ice": ice_servers(&st).await, "max": MAX_FRAME
    })));

    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    let ptx = tx.clone();
    let pinger = tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(25));
        loop {
            iv.tick().await;
            if ptx.send(Message::Ping(Default::default())).is_err() {
                break;
            }
        }
    });

    // ---- relay loop
    let mut window = tokio::time::Instant::now();
    let mut used = 0usize;
    loop {
        let msg = match tokio::time::timeout(IDLE_TIMEOUT, stream.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => break,
        };
        let b = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        if b.len() < 8 + 12 + 16 {
            continue;
        }
        if window.elapsed() > Duration::from_secs(10) {
            window = tokio::time::Instant::now();
            used = 0;
        }
        used += b.len();
        if used > RATE_BYTES {
            continue;
        }
        let to = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let mut out = Vec::with_capacity(b.len());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&b[8..]);
        let out = Message::Binary(out.into());
        let rooms = st.rooms.lock().await;
        if let Some(r) = rooms.get(&room) {
            if to == 0 {
                for (pid, p) in &r.peers {
                    if *pid != id {
                        let _ = p.send(out.clone());
                    }
                }
            } else if to != id {
                if let Some(p) = r.peers.get(&to) {
                    let _ = p.send(out);
                }
            }
        }
    }

    // ---- leave
    {
        let mut rooms = st.rooms.lock().await;
        if let Some(r) = rooms.get_mut(&room) {
            r.peers.remove(&id);
            if r.peers.is_empty() {
                rooms.remove(&room);
            } else {
                let leave = text(serde_json::json!({"t":"leave","id":hex(id)}));
                for p in r.peers.values() {
                    let _ = p.send(leave.clone());
                }
            }
        }
    }
    pinger.abort();
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
}
