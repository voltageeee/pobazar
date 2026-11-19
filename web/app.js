'use strict';
/*
 * побазарь) client.
 *
 * Crypto model
 *   - room key: 32 random bytes, lives only in the URL fragment (#k=...), never sent to the server.
 *   - every frame through the server = AES-256-GCM(HKDF(key)), AAD = room id. The server only relays
 *     opaque bytes; it can't read or forge chat, nicknames, state, SDP or ICE.
 *   - media goes peer-to-peer over WebRTC (DTLS-SRTP). Because the DTLS fingerprints travel inside the
 *     authenticated encrypted signaling, the server can't MITM the media either. TURN (if used) only
 *     sees SRTP ciphertext.
 */

// ------------------------------------------------------------------ utils
const $ = (s, r = document) => r.querySelector(s);
const te = new TextEncoder(), td = new TextDecoder();
const b64u = {
  enc(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  dec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; const b = atob(str); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; },
};
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const rndHex = n => [...rnd(n)].map(b => b.toString(16).padStart(2, '0')).join('');
const hexToBytes = h => { const u = new Uint8Array(8); for (let i = 0; i < 8; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; };
const bytesToHex = u => [...u].map(b => b.toString(16).padStart(2, '0')).join('');
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const fmtSize = n => n < 1024 ? n + ' ' + tr('B') : n < 1048576 ? (n / 1024).toFixed(1) + ' ' + tr('KB') : (n / 1048576).toFixed(1) + ' ' + tr('MB');
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const MAX_FILE = 8 * 1024 * 1024;
const MAX_TEXT = 20000;

// ------------------------------------------------------------------ i18n
const STR = {
  ru: {
    tag: 'голос, демка со звуком и чат со сквозным шифрованием.<br>без аккаунтов, логов и телеметрии.',
    nick: 'ник', nickPh: 'как тебя звать', roomName: 'название комнаты <em>(необязательно)</em>',
    relayLanding: 'скрывать мой ip от собеседников <em>(трафик через relay-сервер, он всё равно зашифрован)</em>',
    create: 'создать комнату', join: 'войти',
    fine: 'ключ комнаты живёт только в ссылке после <code>#</code> — браузер не отправляет его на сервер. сервер видит лишь зашифрованные байты.',
    room: 'комната', e2eeTip: 'сквозное шифрование: AES-256-GCM для сигналинга и чата, DTLS-SRTP p2p для медиа',
    reconnecting: 'переподключение…', copyLink: 'скопировать ссылку', leave: 'выйти',
    attach: 'файл (до 8 МБ)', msgPh: 'сообщение', inRoom: 'в комнате', chat: 'чат', camera: 'камера', members: 'участники',
    yourNick: 'твой ник', settings: 'настройки', language: 'язык', mic: 'микрофон', output: 'вывод звука',
    ns: 'шумоподавление микрофона', quality: 'качество демки', q1440: '1440p · 60 fps (нужен хороший аплинк)',
    echoLbl: 'антиэхо демки <em>(чтобы собеседники не слышали себя при показе всего экрана)</em>',
    echoOn: 'вкл — вычитать голоса из звука демки (рекомендуется)', echoOff: 'выкл',
    relaySet: 'скрывать мой ip (relay) — применяется при переподключении', sounds: 'звуки входа/выхода',
    shareHint: 'звук демки: выбирай <b>вкладку</b>, <b>окно</b> или <b>весь экран</b> и включай галочку «поделиться звуком». вкладка и окно дают звук только этого приложения — эха не бывает вообще.',
    done: 'готово',
    B: 'Б', KB: 'КБ', MB: 'МБ', anon: 'аноним', left: n => `${n} вышел(а)`, joined: n => `${n} зашёл(а)`, renamed: (a, b) => `${a} теперь ${b}`,
    full: 'комната заполнена (максимум 16 человек)', busy: 'сервер перегружен, попробуй позже',
    noMic: 'нет доступа к микрофону — ты в комнате только слушателем. разреши микрофон в адресной строке и нажми кнопку микрофона.',
    camFail: 'камера недоступна: ',
    eSubOn: 'антиэхо: вычитаю голоса', eSubOnTip: ms => `голоса собеседников найдены в звуке демки и вычитаются из него (задержка ${ms} мс)`,
    eSub: 'антиэхо ✓', eSubTip: 'голоса собеседников вычитаются из звука демки, если попадут в него. сейчас вычитать нечего',
    eRestrictTip: 'звук этой вкладки исключён из демки браузером — эха нет', eOkTip: 'захвачен звук только выбранной вкладки/окна — эха нет',
    eRisk: '⚠ эхо', eRiskTip: 'захвачен весь системный звук вместе с голосами собеседников — они слышат себя. настройки → антиэхо демки: вкл',
    noAudio: 'без звука', eNoneTip: 'звук не захвачен',
    noShare: 'браузер не умеет демонстрацию экрана', shareFail: 'не удалось начать демку: ',
    shareSilent: 'демка идёт без звука: выбери вкладку, окно или «весь экран» и включи галочку «поделиться звуком»',
    shareRisk: 'внимание: звук всего экрана захвачен вместе с голосами из этой вкладки — собеседники могут слышать себя. включи «антиэхо демки» в настройках и перезапусти демку.',
    tooLong: (a, b) => `слишком длинно: ${a} / ${b} символов`, tooBig: n => `${n}: больше 8 МБ`,
    noMicBtn: 'нет микро', unmute: 'включить микро', deafOn: 'звук выкл', sound: 'звук', stopShare: 'остановить демку', share: 'демка',
    you: ' (ты)', zoomReset: 'сбросить зум (колёсико — зум, перетаскивание — сдвиг)', screenVol: 'громкость демки', muteScreen: 'выключить звук демки', unmuteScreen: 'включить звук демки', focus: 'крупно', fullscreen: 'на весь экран',
    connFail: 'соединение не удалось, пробую ещё…', connecting: 'соединение…', voiceVol: 'громкость голоса',
    alone: 'тут пока только ты. скопируй ссылку и отправь её — по ней можно зайти.', default: 'по умолчанию',
    micErr: 'микрофон: ', qualLater: 'качество применится к следующей демке', echoLater: 'применится при следующем запуске демки',
    noKey: 'в ссылке нет ключа комнаты (части после #). попроси ссылку целиком.',
    invitedTo: n => `тебя зовут в «${n}»`, invited: 'тебя зовут в комнату', badLink: 'ссылка битая: ',
    copied: 'ссылка скопирована — в ней ключ, отправляй только тем, кого зовёшь', copyPrompt: 'скопируй ссылку:',
    needHttps: 'нужен https — иначе браузер не даст микрофон.',
  },
  en: {
    tag: 'voice, screen share with sound and chat, all end-to-end encrypted.<br>no accounts, no logs, no telemetry.',
    nick: 'nickname', nickPh: 'what should we call you', roomName: 'room name <em>(optional)</em>',
    relayLanding: 'hide my ip from others <em>(traffic goes through a relay server, still encrypted)</em>',
    create: 'create room', join: 'join',
    fine: 'the room key lives only in the link after <code>#</code> — browsers never send it to the server. the server only sees encrypted bytes.',
    room: 'room', e2eeTip: 'end-to-end encryption: AES-256-GCM for signaling and chat, DTLS-SRTP p2p for media',
    reconnecting: 'reconnecting…', copyLink: 'copy link', leave: 'leave',
    attach: 'file (up to 8 MB)', msgPh: 'message', inRoom: 'in the room', chat: 'chat', camera: 'camera', members: 'members',
    yourNick: 'your nickname', settings: 'settings', language: 'language', mic: 'microphone', output: 'audio output',
    ns: 'mic noise suppression', quality: 'screen share quality', q1440: '1440p · 60 fps (needs a good uplink)',
    echoLbl: 'screen share anti-echo <em>(so others don\'t hear themselves when you share the whole screen)</em>',
    echoOn: 'on — subtract voices from screen audio (recommended)', echoOff: 'off',
    relaySet: 'hide my ip (relay) — applies on reconnect', sounds: 'join/leave sounds',
    shareHint: 'screen audio: pick a <b>tab</b>, <b>window</b> or <b>entire screen</b> and tick “share audio”. tab and window capture only that app\'s sound — no echo at all.',
    done: 'done',
    B: 'B', KB: 'KB', MB: 'MB', anon: 'anon', left: n => `${n} left`, joined: n => `${n} joined`, renamed: (a, b) => `${a} is now ${b}`,
    full: 'room is full (16 people max)', busy: 'server is overloaded, try again later',
    noMic: 'no mic access — you\'re listen-only. allow the mic in the address bar and press the mic button.',
    camFail: 'camera unavailable: ',
    eSubOnTip: ms => `others' voices were found in the screen audio and are being subtracted (delay ${ms} ms)`, eSubOn: 'anti-echo: subtracting',
    eSub: 'anti-echo ✓', eSubTip: 'others\' voices get subtracted from the screen audio if they leak into it. nothing to subtract right now',
    eRestrictTip: 'the browser excludes this tab\'s audio from the share — no echo', eOkTip: 'only the selected tab/window audio is captured — no echo',
    eRisk: '⚠ echo', eRiskTip: 'the whole system audio is captured along with others\' voices — they hear themselves. settings → screen share anti-echo: on',
    noAudio: 'no audio', eNoneTip: 'no audio captured',
    noShare: 'this browser can\'t share the screen', shareFail: 'couldn\'t start screen share: ',
    shareSilent: 'sharing without sound: pick a tab, window or “entire screen” and tick “share audio”',
    shareRisk: 'heads up: whole-screen audio is captured together with voices from this tab — others may hear themselves. turn on “screen share anti-echo” in settings and restart the share.',
    tooLong: (a, b) => `too long: ${a} / ${b} characters`, tooBig: n => `${n}: over 8 MB`,
    noMicBtn: 'no mic', unmute: 'unmute', deafOn: 'sound off', sound: 'sound', stopShare: 'stop sharing', share: 'share',
    you: ' (you)', zoomReset: 'reset zoom (wheel to zoom, drag to pan)', screenVol: 'screen volume', muteScreen: 'mute screen audio', unmuteScreen: 'unmute screen audio', focus: 'focus', fullscreen: 'fullscreen',
    connFail: 'connection failed, retrying…', connecting: 'connecting…', voiceVol: 'voice volume',
    alone: 'it\'s just you here. copy the link and send it — anyone with it can join.', default: 'default',
    micErr: 'microphone: ', qualLater: 'quality applies to the next screen share', echoLater: 'applies next time you start sharing',
    noKey: 'the link has no room key (the part after #). ask for the full link.',
    invitedTo: n => `you're invited to “${n}”`, invited: 'you\'re invited to a room', badLink: 'broken link: ',
    copied: 'link copied — it contains the key, send it only to people you invite', copyPrompt: 'copy the link:',
    needHttps: 'https is required — otherwise the browser won\'t give mic access.',
  },
};
const LANGS = Object.keys(STR);
let LANG = 'ru';
const tr = (k, ...a) => { const v = STR[LANG][k] ?? STR.ru[k] ?? k; return typeof v === 'function' ? v(...a) : v; };
function applyI18n(root = document) {
  document.documentElement.lang = LANG;
  root.querySelectorAll('[data-t]').forEach(e => { e.textContent = tr(e.dataset.t); });
  root.querySelectorAll('[data-th]').forEach(e => { e.innerHTML = tr(e.dataset.th); }); // trusted strings from STR only
  root.querySelectorAll('[data-tt]').forEach(e => { e.title = tr(e.dataset.tt); });
  root.querySelectorAll('[data-tp]').forEach(e => { e.placeholder = tr(e.dataset.tp); });
  root.querySelectorAll('#langSw [data-lang]').forEach(b => b.classList.toggle('on', b.dataset.lang === LANG));
  const ls = $('#langSel'); if (ls) ls.value = LANG;
}

const ICONS = {
  mic: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 10a7 7 0 0 0 14 0M12 17v5M8 22h8"/></svg>',
  micoff: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 2l20 20M9 9v1a3 3 0 0 0 5.1 2.1M15 9.3V5a3 3 0 0 0-5.9-.7"/><path d="M5 10a7 7 0 0 0 11.9 5M19 10a7 7 0 0 1-.6 2.8M12 17v5M8 22h8"/></svg>',
  head: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1v-6h3zM3 19a2 2 0 0 0 2 2h1v-6H3z"/></svg>',
  headoff: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 2l20 20M3 18v-6a9 9 0 0 1 2.6-6.4M8.2 3.8A9 9 0 0 1 21 12v4"/><path d="M3 19a2 2 0 0 0 2 2h1v-6H3zM18 15h3v4"/></svg>',
  cam: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 7l-7 5 7 5z"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>',
  screen: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
  chat: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a8 8 0 0 1-11.8 7L3 21l2-6A8 8 0 1 1 21 12z"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/></svg>',
  leave: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>',
  send: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/></svg>',
  clip: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.4 11.1l-9.2 9.2a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2a2 2 0 0 1-2.8-2.8l8.5-8.5"/></svg>',
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  full: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"/></svg>',
  focus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="13" height="18" rx="2"/><path d="M20 3v18"/></svg>',
  vol: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5L6 9H2v6h4l5 4zM15.5 8.5a5 5 0 0 1 0 7M19 5a10 10 0 0 1 0 14"/></svg>',
  volx: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 5L6 9H2v6h4l5 4zM23 9l-6 6M17 9l6 6"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>',
};
const icon = name => { const i = document.createElement('i'); i.dataset.i = name; i.innerHTML = ICONS[name] || ''; return i; };
const setIcon = (btn, name) => { const i = btn.querySelector('i[data-i]'); if (i) { i.dataset.i = name; i.innerHTML = ICONS[name]; } };
function hydrateIcons(root = document) { root.querySelectorAll('i[data-i]').forEach(i => { if (!i.firstChild) i.innerHTML = ICONS[i.dataset.i] || ''; }); }

function hue(str) { let h = 0; for (const c of str) h = (h * 31 + c.codePointAt(0)) >>> 0; return h % 360; }
function avatar(nick, id) { const a = el('div', 'av', ([...(nick || '?').trim()][0] || '?').toUpperCase()); a.style.background = `hsl(${hue(id || nick)} 70% 65%)`; return a; }

function toast(msg, bad, ms = 4000) {
  const t = el('div', 'toast' + (bad ? ' bad' : ''), msg); $('#toasts').append(t);
  setTimeout(() => t.remove(), ms);
}

// ------------------------------------------------------------------ settings (local only)
const LS = 'hush.v1';
const settings = Object.assign({ nick: '', micId: '', outId: '', ns: true, relay: true, quality: '1080p30', sounds: true, antiEcho: 'auto' }, (() => { try { return JSON.parse(localStorage.getItem(LS)) || {}; } catch { return {}; } })());
const saveSettings = () => { try { localStorage.setItem(LS, JSON.stringify(settings)); } catch { } };

const QUALITY = {
  '720p30': { w: 1280, h: 720, fps: 30, br: 2_500_000 },
  '1080p30': { w: 1920, h: 1080, fps: 30, br: 4_500_000 },
  '1080p60': { w: 1920, h: 1080, fps: 60, br: 7_000_000 },
  '1440p60': { w: 2560, h: 1440, fps: 60, br: 10_000_000 },
};

// ------------------------------------------------------------------ state
const S = {
  roomId: '', roomName: '', key: null, aad: null,
  ws: null, myId: null, ice: [], connected: false, leaving: false, retry: 0,
  since: Date.now(),
  mic: { stream: new MediaStream(), track: null, raw: null, muted: false, wasMutedBeforeDeaf: false },
  deaf: false,
  cam: { stream: null },
  screen: { stream: null },
  peers: new Map(),
  focus: null,
  sendQ: Promise.resolve(),
  recvQ: Promise.resolve(),
  seen: new Set(),
  ac: null,
  meters: new Map(), // key -> {an, buf, level}
  unread: 0,
  chatOpen: true, membersOpen: true,
};

// ------------------------------------------------------------------ crypto
async function setupKey(raw) {
  const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  S.key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('hush/v1/salt'), info: te.encode('hush/v1/frames') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  S.aad = te.encode('hush/v1/room/' + S.roomId);
}
async function seal(obj, blob) {
  const j = te.encode(JSON.stringify(obj));
  const extra = blob ? new Uint8Array(blob) : new Uint8Array(0);
  const pt = new Uint8Array(4 + j.length + extra.length);
  new DataView(pt.buffer).setUint32(0, j.length);
  pt.set(j, 4); pt.set(extra, 4 + j.length);
  const iv = rnd(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: S.aad }, S.key, pt));
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12);
  return out;
}
async function open(u8) {
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.subarray(0, 12), additionalData: S.aad }, S.key, u8.subarray(12)));
  const n = new DataView(pt.buffer).getUint32(0);
  const obj = JSON.parse(td.decode(pt.subarray(4, 4 + n)));
  const blob = pt.length > 4 + n ? pt.slice(4 + n) : null;
  return [obj, blob];
}

/** Encrypt and send. `to` = peer hex id or null (broadcast). Ordered. */
function send(to, obj, blob) {
  if (!S.myId) return Promise.resolve();
  obj.from = S.myId; obj.to = to || '*'; obj.n = rndHex(8);
  const ws = S.ws;
  S.sendQ = S.sendQ.then(async () => {
    const ct = await seal(obj, blob);
    const frame = new Uint8Array(8 + ct.length);
    if (to) frame.set(hexToBytes(to)); frame.set(ct, 8);
    if (ws && ws.readyState === 1 && ws === S.ws) ws.send(frame);
  }).catch(e => console.warn('send', e));
  return S.sendQ;
}

// ------------------------------------------------------------------ sounds (generated, no assets)
function beep(up) {
  if (!settings.sounds || !S.ac || S.deaf) return;
  const t = S.ac.currentTime, o = S.ac.createOscillator(), g = S.ac.createGain();
  o.type = 'sine'; o.frequency.setValueAtTime(up ? 520 : 700, t); o.frequency.linearRampToValueAtTime(up ? 780 : 440, t + .14);
  g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.12, t + .02); g.gain.exponentialRampToValueAtTime(0.0001, t + .22);
  o.connect(g).connect(S.ac.destination); if (S.refBus) g.connect(S.refBus); o.start(t); o.stop(t + .25);
}

// ------------------------------------------------------------------ level meters (speaking indicator)
function meter(key, stream) {
  const old = S.meters.get(key);
  if (old && old.stream === stream && old.track === stream.getAudioTracks()[0]) return;
  dropMeter(key);
  const track = stream.getAudioTracks()[0];
  if (!track || !S.ac) return;
  try {
    const src = S.ac.createMediaStreamSource(new MediaStream([track]));
    const an = S.ac.createAnalyser(); an.fftSize = 512; src.connect(an);
    S.meters.set(key, { stream, track, src, an, buf: new Float32Array(an.fftSize), level: 0 });
  } catch (e) { console.warn('meter', e); }
}
function dropMeter(key) { const m = S.meters.get(key); if (m) { try { m.src.disconnect(); } catch { } S.meters.delete(key); } }
function level(key) {
  const m = S.meters.get(key); if (!m) return 0;
  m.an.getFloatTimeDomainData(m.buf);
  let s = 0; for (let i = 0; i < m.buf.length; i++) s += m.buf[i] * m.buf[i];
  const rms = Math.sqrt(s / m.buf.length);
  m.level = Math.max(rms, m.level * 0.82);
  return m.level;
}
setInterval(() => {
  if (!S.myId) return;
  const speak = id => {
    if (id === S.myId) return !S.mic.muted && !S.deaf && level('me') > 0.018;
    const p = S.peers.get(id); if (!p || p.state.muted) return false;
    return level('mic:' + id) > 0.018;
  };
  document.querySelectorAll('[data-speak]').forEach(n => n.classList.toggle('speaking', speak(n.dataset.speak)));
}, 90);

// ------------------------------------------------------------------ peers
function myKinds() {
  const k = {};
  k[S.mic.stream.id] = 'mic';
  if (S.cam.stream) k[S.cam.stream.id] = 'cam';
  if (S.screen.stream) k[S.screen.stream.id] = 'screen';
  return k;
}
function myState() {
  return {
    nick: settings.nick, since: S.since, kinds: myKinds(),
    state: { muted: S.mic.muted || !S.mic.track, deaf: S.deaf, cam: !!S.cam.stream, screen: !!S.screen.stream, screenAudio: !!(S.screen.stream && S.screen.stream.getAudioTracks().length) },
  };
}
function broadcastState() { send(null, Object.assign({ type: 'st' }, myState())); renderAll(); }

function mungeSdp(desc) {
  // ask the remote side to send us stereo, high-bitrate opus (matters for screen-share audio: music, games)
  let sdp = desc.sdp;
  const pts = [...sdp.matchAll(/a=rtpmap:(\d+) opus\/48000\/2/gi)].map(m => m[1]);
  for (const pt of pts) {
    sdp = sdp.replace(new RegExp(`a=fmtp:${pt} (.*)`, 'g'), (line, params) => {
      let p = params.split(';').filter(x => !/^(stereo|sprop-stereo|maxaveragebitrate)=/.test(x.trim()));
      p.push('stereo=1', 'sprop-stereo=1', 'maxaveragebitrate=160000');
      return `a=fmtp:${pt} ${p.join(';')}`;
    });
  }
  return { type: desc.type, sdp };
}

class Peer {
  constructor(id) {
    this.id = id;
    this.nick = '…';
    this.state = {};
    this.kinds = {};
    this.streams = new Map();     // streamId -> MediaStream
    this.audio = new Map();       // streamId -> <audio>
    this.refTaps = new Map();     // streamId -> {src, g} feeding S.refBus
    this.volume = 1;
    this.screenVolume = 1;
    this.polite = S.myId > id;
    this.createPc();
  }

  /*
   * Connection setup is deterministic: the impolite side (smaller id) always sends the first offer,
   * the polite side attaches its media only once that offer arrives. No initial offer glare — Chrome
   * sometimes wedges ICE gathering forever when an offer is rolled back while TURN allocation is in
   * flight. A watchdog rebuilds the connection from scratch if it still doesn't come up.
   */
  createPc() {
    this.makingOffer = false;
    this.ignoreOffer = false;
    this.senders = { mic: null, cam: [], screen: [] };
    this.started = !this.polite;
    this.bornAt = performance.now();
    this.restarted = false;
    const pc = this.pc = new RTCPeerConnection({
      iceServers: S.ice,
      iceTransportPolicy: settings.relay && S.ice.some(s => s.username) ? 'relay' : 'all',
      bundlePolicy: 'max-bundle',
    });
    pc.onicecandidate = ({ candidate }) => { if (candidate && pc === this.pc) send(this.id, { type: 'ice', c: candidate.toJSON() }); };
    pc.onnegotiationneeded = async () => {
      if (!this.started || pc !== this.pc) return;
      try {
        this.makingOffer = true;
        await pc.setLocalDescription();
        send(this.id, { type: 'sdp', d: mungeSdp(pc.localDescription) });
      } catch (e) { console.warn('negotiation', e); }
      finally { this.makingOffer = false; }
    };
    pc.ontrack = e => {
      const st = e.streams[0]; if (!st) return;
      this.streams.set(st.id, st);
      st.onremovetrack = () => renderAll();
      st.onaddtrack = () => renderAll();
      e.track.onunmute = () => renderAll();
      e.track.onended = () => renderAll();
      renderAll();
    };
    pc.onconnectionstatechange = () => {
      if (pc !== this.pc) return;
      if (pc.connectionState === 'connected') this.restarted = false;
      if (pc.connectionState === 'failed' && !this.polite) { try { pc.restartIce(); } catch { } }
      if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') this.bornAt = performance.now();
      renderMembers();
    };
    if (this.started) this.addLocal(true);
  }

  addLocal(forceOffer) {
    if (S.mic.track) this.senders.mic = this.pc.addTrack(S.mic.track, S.mic.stream);
    else if (forceOffer) this.pc.addTransceiver('audio', { direction: 'recvonly' }); // listen-only: still need an offer
    if (S.cam.stream) this.addStream('cam');
    if (S.screen.stream) this.addStream('screen');
  }

  /** called every few seconds */
  watchdog() {
    const cs = this.pc.connectionState;
    if (cs === 'connected' || cs === 'closed' || this.polite) return;
    const age = performance.now() - this.bornAt;
    if (age > 10000 && !this.restarted) { this.restarted = true; try { this.pc.restartIce(); } catch { } }
    else if (age > 20000) { send(this.id, { type: 'reset' }); this.rebuild(); }
  }

  rebuild() {
    try { this.pc.close(); } catch { }
    this.streams.clear();
    this.createPc();
    renderAll();
  }

  addStream(kind) {
    if (!this.started) return; // will be attached when the first offer arrives
    const st = S[kind].stream; if (!st) return;
    this.senders[kind] = [];
    for (const t of st.getTracks()) {
      const init = { direction: 'sendonly', streams: [st] };
      if (t.kind === 'video') {
        const q = QUALITY[settings.quality] || QUALITY['1080p30'];
        init.sendEncodings = [kind === 'screen' ? { maxBitrate: q.br, maxFramerate: q.fps } : { maxBitrate: 1_500_000, maxFramerate: 30 }];
      } else if (kind === 'screen') {
        init.sendEncodings = [{ maxBitrate: 160_000 }];
      }
      try { this.senders[kind].push(this.pc.addTransceiver(t, init).sender); } catch (e) { console.warn('addTransceiver', e); }
    }
  }
  removeStream(kind) {
    for (const s of this.senders[kind] || []) { try { this.pc.removeTrack(s); } catch { } }
    this.senders[kind] = [];
  }
  setMicTrack(track) {
    if (!this.started) return;
    if (this.senders.mic) this.senders.mic.replaceTrack(track).catch(() => { });
    else if (track) this.senders.mic = this.pc.addTrack(track, S.mic.stream);
  }

  async onSignal(o) {
    const pc = this.pc;
    if (o.type === 'reset') { if (this.polite) this.rebuild(); return; }
    if (o.type === 'sdp') {
      const d = o.d;
      const collision = d.type === 'offer' && (this.makingOffer || pc.signalingState !== 'stable');
      this.ignoreOffer = !this.polite && collision;
      if (this.ignoreOffer) return;
      await pc.setRemoteDescription(d);
      if (d.type === 'offer') {
        if (!this.started) { this.started = true; this.addLocal(false); } // reuses the offered audio transceiver for our mic
        await pc.setLocalDescription();
        send(this.id, { type: 'sdp', d: mungeSdp(pc.localDescription) });
      }
    } else if (o.type === 'ice') {
      try { await pc.addIceCandidate(o.c); } catch (e) { if (!this.ignoreOffer) console.warn('ice', e); }
    }
  }

  apply(o) {
    if (typeof o.nick === 'string') this.nick = o.nick.slice(0, 32) || tr('anon');
    if (o.state && typeof o.state === 'object') this.state = o.state;
    if (o.kinds && typeof o.kinds === 'object') this.kinds = o.kinds;
    if (typeof o.since === 'number' && o.since > 1e12 && o.since < S.since) S.since = o.since;
  }

  /** live streams of a kind */
  stream(kind) {
    for (const [id, st] of this.streams) if (this.kinds[id] === kind) return st;
    return null;
  }

  close() {
    try { this.pc.close(); } catch { }
    for (const a of this.audio.values()) { a.srcObject = null; a.remove(); }
    this.audio.clear();
    for (const tap of this.refTaps.values()) { try { tap.src.disconnect(); tap.g.disconnect(); } catch { } }
    this.refTaps.clear();
    dropMeter('mic:' + this.id);
  }
}

setInterval(() => { for (const p of S.peers.values()) p.watchdog(); }, 3000);

function ensurePeer(id) {
  let p = S.peers.get(id);
  if (!p) { p = new Peer(id); S.peers.set(id, p); }
  return p;
}

// ------------------------------------------------------------------ connection
function wsUrl() { return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/' + S.roomId; }

function connect() {
  const ws = new WebSocket(wsUrl());
  ws.binaryType = 'arraybuffer';
  S.ws = ws;
  ws.onmessage = ev => {
    if (typeof ev.data === 'string') {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      S.recvQ = S.recvQ.then(() => onServer(m)).catch(e => console.warn(e));
    } else {
      const u8 = new Uint8Array(ev.data);
      S.recvQ = S.recvQ.then(() => onFrame(u8)).catch(e => console.warn('frame', e));
    }
  };
  ws.onclose = () => {
    if (ws !== S.ws) return;
    S.connected = false; S.myId = null;
    for (const p of S.peers.values()) p.close();
    S.peers.clear();
    renderAll();
    if (S.leaving || S.fatal) return;
    $('#netState').hidden = false;
    const delay = Math.min(10000, 800 * 2 ** S.retry++);
    setTimeout(() => { if (!S.leaving) connect(); }, delay);
  };
}

async function onServer(m) {
  if (m.t === 'welcome') {
    S.myId = m.id; S.ice = Array.isArray(m.ice) ? m.ice : []; S.connected = true; S.retry = 0;
    $('#netState').hidden = true;
    send(null, Object.assign({ type: 'hi' }, myState()));
    renderAll();
  } else if (m.t === 'leave') {
    const p = S.peers.get(m.id);
    if (p) { p.close(); S.peers.delete(m.id); sysMsg(tr('left', p.nick)); beep(false); if (S.focus && S.focus.startsWith(m.id)) S.focus = null; renderAll(); }
  } else if (m.t === 'error') {
    S.fatal = true;
    const t = m.e === 'full' ? tr('full') : tr('busy');
    toast(t, true, 10000); sysMsg(t);
  }
}

async function onFrame(u8) {
  if (u8.length < 8 + 12 + 16 || !S.key) return;
  const from = bytesToHex(u8.subarray(0, 8));
  let o, blob;
  try { [o, blob] = await open(u8.subarray(8)); } catch { return; } // not encrypted with our key → ignore
  // the inner (authenticated) envelope must match the relay's outer routing
  if (o.from !== from || (o.to !== '*' && o.to !== S.myId) || from === S.myId) return;
  if (typeof o.n !== 'string' || S.seen.has(o.n)) return; // replay
  S.seen.add(o.n); if (S.seen.size > 20000) S.seen.clear();

  switch (o.type) {
    case 'hi': {
      const isNew = !S.peers.has(from);
      const p = ensurePeer(from); p.apply(o);
      send(from, Object.assign({ type: 'st' }, myState()));
      if (isNew) { sysMsg(tr('joined', p.nick)); beep(true); }
      renderAll(); break;
    }
    case 'st': { const p = ensurePeer(from); const old = p.nick; p.apply(o); if (old !== '…' && old !== p.nick) sysMsg(tr('renamed', old, p.nick)); renderAll(); break; }
    case 'sdp': case 'ice': case 'reset': await ensurePeer(from).onSignal(o); break;
    case 'chat': if (typeof o.text === 'string') addMsg(from, o.text.slice(0, MAX_TEXT), o.ts); break;
    case 'file': if (blob) addFile(from, o, blob); break;
  }
}

// ------------------------------------------------------------------ local media
async function getMic(deviceId) {
  return navigator.mediaDevices.getUserMedia({
    audio: {
      deviceId: deviceId ? { exact: deviceId } : undefined,
      echoCancellation: true, noiseSuppression: !!settings.ns, autoGainControl: true,
      channelCount: 1, sampleRate: 48000,
    },
  });
}
async function initMic() {
  try {
    let st;
    try { st = await getMic(settings.micId); } catch (e) { if (settings.micId && e.name === 'OverconstrainedError') st = await getMic(''); else throw e; }
    setMic(st.getAudioTracks()[0], st);
  } catch (e) {
    toast(tr('noMic'), true, 8000);
  }
}
function setMic(track, raw) {
  const old = S.mic.track;
  if (old) { S.mic.stream.removeTrack(old); old.stop(); }
  if (S.mic.raw && S.mic.raw !== raw) S.mic.raw.getTracks().forEach(t => t.stop());
  S.mic.track = track; S.mic.raw = raw;
  if (track) {
    S.mic.stream.addTrack(track);
    track.enabled = !S.mic.muted && !S.deaf;
    meter('me', S.mic.stream);
  }
  for (const p of S.peers.values()) p.setMicTrack(track);
  broadcastState();
}

async function toggleMute() {
  if (!S.mic.track) { await initMic(); if (!S.mic.track) return; S.mic.muted = false; }
  else S.mic.muted = !S.mic.muted;
  if (!S.mic.muted && S.deaf) { S.deaf = false; applyDeaf(); }
  S.mic.track.enabled = !S.mic.muted && !S.deaf;
  broadcastState();
}
function toggleDeaf() {
  S.deaf = !S.deaf;
  if (S.deaf) { S.mic.wasMutedBeforeDeaf = S.mic.muted; S.mic.muted = true; }
  else S.mic.muted = S.mic.wasMutedBeforeDeaf;
  if (S.mic.track) S.mic.track.enabled = !S.mic.muted && !S.deaf;
  applyDeaf();
  broadcastState();
}
function applyDeaf() { for (const p of S.peers.values()) for (const a of p.audio.values()) a.muted = S.deaf; renderAudio(); }

async function toggleCam() {
  if (S.cam.stream) return stopCam();
  try {
    S.cam.stream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } } });
  } catch (e) { toast(tr('camFail') + e.message, true); return; }
  S.cam.stream.getVideoTracks()[0].onended = stopCam;
  broadcastState();
  for (const p of S.peers.values()) p.addStream('cam');
}
function stopCam() {
  if (!S.cam.stream) return;
  for (const p of S.peers.values()) p.removeStream('cam');
  S.cam.stream.getTracks().forEach(t => t.stop());
  S.cam.stream = null;
  broadcastState();
}

function ensureEchoWorklet() {
  if (!S.echoReady) S.echoReady = S.ac.audioWorklet.addModule('/echo-worklet.js').catch(e => { S.echoReady = null; throw e; });
  return S.echoReady;
}
function echoBadge() {
  const st = S.screen.subStats;
  switch (S.screen.echo) {
    case 'sub':
      if (st && Date.now() - (S.screen.subSeen || 0) < 8000) return [tr('eSubOn'), 'aec', tr('eSubOnTip', Math.round(st.lagMs))];
      return [tr('eSub'), 'ok', tr('eSubTip')];
    case 'restrict': return ['echo ok', 'ok', tr('eRestrictTip')];
    case 'ok': return ['echo ok', 'ok', tr('eOkTip')];
    case 'risk': return [tr('eRisk'), 'risk', tr('eRiskTip')];
    default: return [tr('noAudio'), 'none', tr('eNoneTip')];
  }
}
function updateEchoBadge() {
  const b = tileNodes.get('me:screen')?.label.querySelector('.echo');
  if (!b) return;
  const [txt, cls, tip] = echoBadge();
  b.textContent = txt; b.className = 'echo ' + cls; b.title = tip;
}

async function toggleScreen() {
  if (S.screen.stream) return stopScreen();
  if (!navigator.mediaDevices.getDisplayMedia) { toast(tr('noShare'), true); return; }
  const q = QUALITY[settings.quality] || QUALITY['1080p30'];
  /*
   * Echo problem: sharing the whole screen captures the system mix, which includes the voices this
   * tab plays → listeners hear themselves. Defences:
   *   1. restrictOwnAudio — browser excludes this tab's own output (often advertised but not applied).
   *   2. windowAudio:'window' — sharing a single window captures only that app's audio.
   *   3. echo-sub worklet — we know exactly what we play, so we find it in the capture and subtract it
   *      (delay search + least-squares filter). Harmless when there is nothing to remove.
   */
  const sc = navigator.mediaDevices.getSupportedConstraints();
  const mode = settings.antiEcho === 'off' ? 'off' : 'auto';
  const audio = {
    echoCancellation: false, noiseSuppression: false, autoGainControl: false,
    channelCount: { ideal: 2 }, sampleRate: { ideal: 48000 },
    restrictOwnAudio: true, suppressLocalAudioPlayback: false,
  };
  const opts = {
    video: { width: { ideal: q.w, max: q.w }, height: { ideal: q.h, max: q.h }, frameRate: { ideal: q.fps, max: q.fps } },
    audio,
    systemAudio: 'include',
    windowAudio: 'window',
    selfBrowserSurface: 'exclude',
    surfaceSwitching: 'include',
    monitorTypeSurfaces: 'include',
  };
  let st;
  try {
    try { st = await navigator.mediaDevices.getDisplayMedia(opts); }
    catch (e) {
      // an older browser that knows `windowAudio` with other values rejects the dictionary up front
      if (e.name !== 'TypeError') throw e;
      delete opts.windowAudio;
      st = await navigator.mediaDevices.getDisplayMedia(opts);
    }
  } catch (e) {
    if (e.name !== 'NotAllowedError') toast(tr('shareFail') + e.message, true);
    return;
  }
  const v = st.getVideoTracks()[0];
  if (v) { v.contentHint = q.fps >= 60 ? 'motion' : 'detail'; v.onended = stopScreen; }
  const surface = v?.getSettings().displaySurface || '';
  const a = st.getAudioTracks()[0];
  S.screen.echo = 'none';
  if (!a) {
    toast(tr('shareSilent'), false, 9000);
  } else {
    let s = a.getSettings();
    if (sc.restrictOwnAudio && !s.restrictOwnAudio) {
      try { await a.applyConstraints(Object.assign({}, audio, { restrictOwnAudio: true })); } catch { }
      s = a.getSettings();
    }
    S.screen.echo = s.restrictOwnAudio ? 'restrict' : surface === 'monitor' ? 'risk' : 'ok';
  }
  S.screen.surface = surface;
  S.screen.raw = st;
  S.screen.sub = null; S.screen.subStats = null;
  let send = st;
  if (a && mode !== 'off') {
    try {
      await ensureEchoWorklet();
      S.ac.resume().catch(() => { });
      const src = S.ac.createMediaStreamSource(new MediaStream([a]));
      const node = new AudioWorkletNode(S.ac, 'echo-sub', {
        numberOfInputs: 2, numberOfOutputs: 1, outputChannelCount: [2],
        channelCount: 2, channelCountMode: 'explicit', channelInterpretation: 'speakers',
      });
      const dst = S.ac.createMediaStreamDestination(); dst.channelCount = 2;
      src.connect(node, 0, 0); S.refBus.connect(node, 0, 1); node.connect(dst);
      const pa = dst.stream.getAudioTracks()[0];
      node.port.onmessage = e => { S.screen.subStats = e.data; if (e.data.apply) S.screen.subSeen = Date.now(); updateEchoBadge(); };
      S.screen.sub = { src, node, dst, pa };
      send = new MediaStream([v, pa].filter(Boolean));
      S.screen.echo = 'sub';
    } catch (e) { console.warn('echo-sub', e); }
  }
  if (S.screen.echo === 'risk') toast(tr('shareRisk'), true, 10000);
  S.screen.stream = send;
  broadcastState();
  for (const p of S.peers.values()) p.addStream('screen');
}
function stopScreen() {
  if (!S.screen.stream) return;
  for (const p of S.peers.values()) p.removeStream('screen');
  S.screen.stream.getTracks().forEach(t => t.stop());
  S.screen.raw?.getTracks().forEach(t => t.stop());
  if (S.screen.sub) { try { S.screen.sub.src.disconnect(); S.refBus.disconnect(S.screen.sub.node); S.screen.sub.node.disconnect(); } catch { } }
  S.screen.sub = null; S.screen.raw = null; S.screen.subStats = null;
  S.screen.stream = null;
  if (S.focus === 'me:screen') S.focus = null;
  broadcastState();
}

// ------------------------------------------------------------------ chat
function linkify(parent, text) {
  const re = /\bhttps?:\/\/[^\s<>"']+/gi; let last = 0, m;
  while ((m = re.exec(text))) {
    let url = m[0].replace(/[),.!?:;]+$/, '');
    parent.append(text.slice(last, m.index));
    const a = el('a', null, url); a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer nofollow';
    parent.append(a); last = m.index + url.length; re.lastIndex = last;
  }
  parent.append(text.slice(last));
}
function nickOf(id) { return id === S.myId ? settings.nick : (S.peers.get(id)?.nick || '?'); }
function msgShell(from, ts) {
  const box = $('#msgs');
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const m = el('div', 'msg');
  const meta = el('div', 'meta');
  const who = el('span', 'who', nickOf(from)); who.style.color = `hsl(${hue(from)} 70% 70%)`;
  const d = new Date(typeof ts === 'number' ? ts : Date.now());
  meta.append(who, el('span', 'when', d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })));
  m.append(meta);
  box.append(m);
  const done = () => { if (stick || from === S.myId) box.scrollTop = box.scrollHeight; if (from !== S.myId && !S.chatOpen) { S.unread++; renderUnread(); } };
  return [m, done];
}
function addMsg(from, text, ts) {
  const [m, done] = msgShell(from, ts);
  const t = el('div', 'text'); linkify(t, text); m.append(t); done();
}
const SAFE_IMG = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif']);
function addFile(from, o, bytes) {
  const [m, done] = msgShell(from, o.ts);
  const name = String(o.name || 'file').slice(0, 200);
  const mime = SAFE_IMG.has(o.mime) ? o.mime : 'application/octet-stream'; // never render untrusted html/svg in our origin
  const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
  if (mime !== 'application/octet-stream') {
    const img = el('img', 'att'); img.src = url; img.alt = name; img.onload = done;
    img.onclick = () => { const v = el('div', 'viewer'); const i = el('img'); i.src = url; v.append(i); v.onclick = () => v.remove(); document.body.append(v); };
    m.append(img);
  }
  const a = el('a', 'file'); a.href = url; a.download = name;
  a.append(icon('file'), el('span', null, name), el('small', null, fmtSize(bytes.length)));
  m.append(a); done();
}
function sysMsg(text) { const box = $('#msgs'); box.append(el('div', 'msg sys', text)); box.scrollTop = box.scrollHeight; }

function sendText() {
  const ta = $('#msgInput');
  const text = ta.value.replace(/\s+$/, '');
  if (!text.trim()) return;
  if (text.length > MAX_TEXT) { toast(tr('tooLong', text.length, MAX_TEXT), true); return; }
  const ts = Date.now();
  send(null, { type: 'chat', text, ts });
  addMsg(S.myId, text, ts);
  ta.value = ''; autoGrow();
}
async function sendFiles(files) {
  for (const f of files) {
    if (f.size > MAX_FILE) { toast(tr('tooBig', f.name), true); continue; }
    const bytes = new Uint8Array(await f.arrayBuffer());
    const o = { type: 'file', name: f.name, mime: f.type, size: f.size, ts: Date.now() };
    send(null, Object.assign({}, o), bytes);
    addFile(S.myId, o, bytes);
  }
}
function autoGrow() { const ta = $('#msgInput'); ta.style.height = 'auto'; ta.style.height = Math.min(160, ta.scrollHeight + 2) + 'px'; }
function renderUnread() { const b = $('#unread'); b.hidden = !S.unread; b.textContent = S.unread > 99 ? '99+' : S.unread; }

// ------------------------------------------------------------------ rendering
function renderAll() { renderControls(); renderAudio(); renderTiles(); renderMembers(); renderLobby(); }

function renderControls() {
  const mute = $('#muteBtn'), deaf = $('#deafBtn'), cam = $('#camBtn'), share = $('#shareBtn');
  const muted = S.mic.muted || !S.mic.track;
  mute.classList.toggle('off', muted); setIcon(mute, muted ? 'micoff' : 'mic');
  mute.querySelector('span').textContent = !S.mic.track ? tr('noMicBtn') : muted ? tr('unmute') : tr('mic');
  deaf.classList.toggle('off', S.deaf); setIcon(deaf, S.deaf ? 'headoff' : 'head');
  deaf.querySelector('span').textContent = S.deaf ? tr('deafOn') : tr('sound');
  cam.classList.toggle('on', !!S.cam.stream);
  share.classList.toggle('live', !!S.screen.stream);
  share.querySelector('span').textContent = S.screen.stream ? tr('stopShare') : tr('share');
}

/** one hidden <audio> per remote stream with audio (mic, screen) */
function renderAudio() {
  const sink = $('#audioSink');
  for (const p of S.peers.values()) {
    const want = new Set();
    for (const [sid, st] of p.streams) {
      const kind = p.kinds[sid];
      if (kind !== 'mic' && kind !== 'screen') continue;
      if (!st.getAudioTracks().length) continue;
      want.add(sid);
      let a = p.audio.get(sid);
      if (!a) {
        a = document.createElement('audio'); a.autoplay = true; a.srcObject = st;
        if (settings.outId && a.setSinkId) a.setSinkId(settings.outId).catch(() => { });
        sink.append(a); p.audio.set(sid, a);
        a.play().catch(() => { });
      }
      a.muted = S.deaf;
      a.volume = clamp(kind === 'screen' ? p.screenVolume : p.volume, 0, 1);
      // reference for the screen-share echo remover: exactly what we play, with the same volume
      let tap = p.refTaps.get(sid);
      if (!tap && S.refBus) {
        try { const src = S.ac.createMediaStreamSource(st); const g = S.ac.createGain(); src.connect(g).connect(S.refBus); tap = { src, g }; p.refTaps.set(sid, tap); } catch { }
      }
      if (tap) tap.g.gain.value = S.deaf ? 0 : a.volume;
      if (kind === 'mic') meter('mic:' + p.id, st);
    }
    for (const [sid, a] of p.audio) if (!want.has(sid)) { a.srcObject = null; a.remove(); p.audio.delete(sid); }
    for (const [sid, tap] of p.refTaps) if (!want.has(sid)) { try { tap.src.disconnect(); tap.g.disconnect(); } catch { } p.refTaps.delete(sid); }
  }
}

const tileNodes = new Map(); // key -> {node, video}
function tilesWanted() {
  const out = [];
  if (S.screen.stream) out.push({ key: 'me:screen', id: S.myId, kind: 'screen', stream: S.screen.stream, me: true });
  if (S.cam.stream) out.push({ key: 'me:cam', id: S.myId, kind: 'cam', stream: S.cam.stream, me: true });
  for (const p of S.peers.values()) {
    for (const kind of ['screen', 'cam']) {
      if (!p.state[kind]) continue;
      const st = p.stream(kind);
      if (!st || !st.getVideoTracks().some(t => t.readyState === 'live')) continue;
      out.push({ key: p.id + ':' + kind, id: p.id, kind, stream: st, peer: p });
    }
  }
  return out;
}
function renderTiles() {
  const box = $('#tiles');
  const want = tilesWanted();
  const keys = new Set(want.map(w => w.key));
  for (const [k, t] of tileNodes) if (!keys.has(k)) { t.video.srcObject = null; t.node.remove(); tileNodes.delete(k); }
  if (S.focus && !keys.has(S.focus)) S.focus = null;

  let idx = 0;
  for (const w of want) {
    let t = tileNodes.get(w.key);
    if (!t) {
      const node = el('div', 'tile' + (w.kind === 'cam' && w.me ? ' mirror' : ''));
      const video = document.createElement('video'); video.autoplay = true; video.playsInline = true; video.muted = true;
      const label = el('div', 'label');
      const tools = el('div', 'tools');
      node.append(video, label, tools);
      node.ondblclick = () => fullscreen(node);
      // fullscreen: hide label/controls/cursor after a moment of mouse inactivity (YouTube-style)
      let idleT = null;
      const wake = () => {
        node.classList.remove('idle');
        clearTimeout(idleT);
        if (document.fullscreenElement === node) idleT = setTimeout(() => {
          if (document.fullscreenElement === node && !node.querySelector('.tools:hover, input:active, .ctxvol')) node.classList.add('idle');
          else wake();
        }, 2500);
      };
      node.addEventListener('mousemove', wake);
      node.addEventListener('mousedown', wake);
      node.addEventListener('fullscreenchange', wake);
      t = { node, video, label, tools, volKey: null };
      tileNodes.set(w.key, t);
      if (w.kind === 'screen') attachZoom(t);
      buildTools(t, w);
    }
    if (t.video.srcObject !== w.stream) { t.video.srcObject = w.stream; t.video.play().catch(() => { }); }
    t.node.dataset.speak = w.kind === 'cam' ? w.id : '';
    if (w.kind !== 'cam') t.node.classList.remove('speaking');
    t.label.textContent = '';
    t.label.append(icon(w.kind === 'screen' ? 'screen' : 'cam'), el('span', null, (w.me ? settings.nick + tr('you') : w.peer.nick)));
    if (w.kind === 'screen' && !w.me && !w.stream.getAudioTracks().length) t.label.append(el('span', 'noaudio', tr('noAudio')));
    if (w.kind === 'screen' && w.me) {
      const [txt, cls, tip] = echoBadge();
      const b = el('span', 'echo ' + cls, txt); b.title = tip;
      t.label.append(b);
    }
    t.node.classList.toggle('big', S.focus === w.key);
    if (box.children[idx] !== t.node) box.insertBefore(t.node, box.children[idx] || null);
    idx++;
  }
  const n = want.length;
  box.classList.toggle('focus', !!S.focus);
  box.classList.toggle('solo', !!S.focus && n === 1);
  if (!S.focus) {
    const cols = n <= 1 ? 1 : n <= 4 ? 2 : n <= 9 ? 3 : 4;
    box.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
  } else box.style.gridTemplateColumns = '';
}
function buildTools(t, w) {
  t.tools.textContent = '';
  if (w.kind === 'screen' && !w.me) {
    const wrap = el('div', 'tvol'); wrap.append(icon('vol'));
    const r = document.createElement('input'); r.type = 'range'; r.min = 0; r.max = 100; r.value = Math.round(w.peer.screenVolume * 100);
    r.title = tr('screenVol');
    r.oninput = () => setScreenVol(t, w.peer, r.value / 100);
    wrap.append(r); t.tools.append(wrap);
    t.volRange = r;
    // right click anywhere on the stream → small volume popup at the cursor
    t.node.oncontextmenu = e => { e.preventDefault(); openVolMenu(t, w.peer, e); };
  }
  const f = el('button', 'iconbtn'); f.title = tr('focus'); f.append(icon('focus'));
  f.onclick = e => { e.stopPropagation(); S.focus = S.focus === w.key ? null : w.key; renderTiles(); };
  const fs = el('button', 'iconbtn'); fs.title = tr('fullscreen'); fs.append(icon('full'));
  fs.onclick = e => { e.stopPropagation(); fullscreen(t.node); };
  t.tools.append(f, fs);
}
/** Discord-style zoom on a screen share: wheel zooms at the cursor, drag pans, badge resets. */
function attachZoom(t) {
  const { node, video } = t;
  const z = { s: 1, x: 0, y: 0 }; // x/y = translation as a fraction of the tile size
  const badge = el('button', 'zoomind'); badge.type = 'button'; badge.hidden = true; node.append(badge);
  const apply = () => {
    const w = node.clientWidth, h = node.clientHeight;
    z.x = clamp(z.x, 1 - z.s, 0); z.y = clamp(z.y, 1 - z.s, 0);
    video.style.transform = z.s === 1 ? '' : `translate(${z.x * w}px, ${z.y * h}px) scale(${z.s})`;
    node.classList.toggle('zoomed', z.s > 1);
    badge.hidden = z.s === 1; badge.textContent = z.s.toFixed(1) + '× ✕'; badge.title = tr('zoomReset');
  };
  const zoomAt = (ns, cx, cy) => { // cx/cy: cursor position as a fraction of the tile
    ns = clamp(ns, 1, 8); if (Math.abs(ns - 1) < .02) ns = 1;
    z.x = cx - (cx - z.x) * ns / z.s; z.y = cy - (cy - z.y) * ns / z.s; z.s = ns;
    if (ns === 1) z.x = z.y = 0;
    apply();
  };
  t.zoomReset = () => { z.s = 1; z.x = z.y = 0; apply(); };
  node.addEventListener('wheel', e => {
    if (e.target.closest('.tools, .ctxvol')) return;
    e.preventDefault();
    const b = node.getBoundingClientRect();
    zoomAt(z.s * Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0015)), (e.clientX - b.left) / b.width, (e.clientY - b.top) / b.height);
  }, { passive: false });
  let drag = null;
  node.addEventListener('mousedown', e => {
    if (e.button !== 0 || z.s === 1 || e.target.closest('.tools, .ctxvol, .zoomind')) return;
    e.preventDefault(); drag = { x: e.clientX, y: e.clientY, zx: z.x, zy: z.y }; node.classList.add('panning');
  });
  window.addEventListener('mousemove', e => {
    if (!drag) return;
    z.x = drag.zx + (e.clientX - drag.x) / node.clientWidth; z.y = drag.zy + (e.clientY - drag.y) / node.clientHeight; apply();
  });
  window.addEventListener('mouseup', () => { if (drag) { drag = null; node.classList.remove('panning'); } });
  badge.onclick = e => { e.stopPropagation(); t.zoomReset(); };
  badge.ondblclick = e => e.stopPropagation();
  new ResizeObserver(apply).observe(node);
}

function setScreenVol(t, peer, v) {
  v = clamp(Math.round(v * 100) / 100, 0, 1);
  if (v > 0) peer.screenVolPrev = v;
  peer.screenVolume = v;
  if (t.volRange) t.volRange.value = Math.round(v * 100);
  t.volMenu?.sync();
  renderAudio();
}
function closeVolMenu() { document.querySelectorAll('.tile .ctxvol').forEach(m => m.remove()); for (const t of tileNodes.values()) t.volMenu = null; }
function openVolMenu(t, peer, e) {
  closeVolMenu();
  const m = el('div', 'ctxvol');
  const head = el('div', 'cvhead', tr('screenVol') + ' · ' + peer.nick);
  const row = el('div', 'cvrow');
  const mute = el('button', 'iconbtn'); mute.type = 'button';
  const r = document.createElement('input'); r.type = 'range'; r.min = 0; r.max = 100;
  const pct = el('span', 'cvpct');
  row.append(mute, r, pct);
  m.append(head, row);
  const sync = () => {
    const v = Math.round(peer.screenVolume * 100);
    r.value = v; pct.textContent = v + '%';
    mute.textContent = ''; mute.append(icon(v ? 'vol' : 'volx')); mute.title = v ? tr('muteScreen') : tr('unmuteScreen');
    mute.classList.toggle('off', !v);
  };
  r.oninput = () => setScreenVol(t, peer, r.value / 100);
  mute.onclick = () => setScreenVol(t, peer, peer.screenVolume ? 0 : (peer.screenVolPrev || 1));
  m.onwheel = ev => { ev.preventDefault(); ev.stopPropagation(); setScreenVol(t, peer, peer.screenVolume + (ev.deltaY < 0 ? .05 : -.05)); };
  m.oncontextmenu = ev => { ev.preventDefault(); ev.stopPropagation(); };
  m.onmousedown = m.ondblclick = ev => ev.stopPropagation();
  t.volMenu = { sync }; sync();
  t.node.append(m);
  // place at the cursor, kept inside the tile
  const b = t.node.getBoundingClientRect();
  const x = clamp(e.clientX - b.left, 8, b.width - m.offsetWidth - 8), y = clamp(e.clientY - b.top, 8, b.height - m.offsetHeight - 8);
  m.style.left = x + 'px'; m.style.top = y + 'px';
  r.focus();
}
document.addEventListener('mousedown', e => { if (!e.target.closest?.('.ctxvol')) closeVolMenu(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeVolMenu(); });

function fullscreen(node) {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => { });
  else node.requestFullscreen?.().catch(() => { });
}

function memberRow(id, nick, state, peer) {
  const li = el('li', 'mem'); li.dataset.speak = id;
  const row = el('div', 'row');
  row.append(avatar(nick, id));
  const n = el('div', 'nick', nick); if (!peer) n.append(el('small', null, tr('you')));
  row.append(n);
  const ic = el('div', 'icons');
  if (state.screen) { const i = icon('screen'); i.classList.add('live'); i.title = tr('share'); ic.append(i); }
  if (state.cam) { const i = icon('cam'); i.classList.add('live'); ic.append(i); }
  if (state.deaf) { const i = icon('headoff'); i.classList.add('red'); ic.append(i); }
  else if (state.muted) { const i = icon('micoff'); i.classList.add('red'); ic.append(i); }
  row.append(ic);
  li.append(row);
  if (peer) {
    const cs = peer.pc.connectionState;
    if (cs !== 'connected' && cs !== 'new') li.append(el('div', 'conn', cs === 'failed' ? tr('connFail') : tr('connecting')));
    const vol = el('div', 'vol'); vol.append(icon('vol'));
    const r = document.createElement('input'); r.type = 'range'; r.min = 0; r.max = 100; r.value = Math.round(peer.volume * 100);
    r.title = tr('voiceVol');
    const lbl = el('span', null, r.value + '%');
    r.oninput = () => { peer.volume = r.value / 100; lbl.textContent = r.value + '%'; renderAudio(); };
    r.onfocus = () => li.classList.add('open'); r.onblur = () => li.classList.remove('open');
    vol.append(r, lbl); li.append(vol);
  }
  return li;
}
function renderMembers() {
  const ul = $('#memberList');
  if (ul.contains(document.activeElement) && document.activeElement.type === 'range') return; // don't kill a slider mid-drag
  ul.textContent = '';
  ul.append(memberRow(S.myId || 'me', settings.nick, myState().state, null));
  const peers = [...S.peers.values()].sort((a, b) => a.nick.localeCompare(b.nick));
  for (const p of peers) ul.append(memberRow(p.id, p.nick, p.state, p));
  $('#memberCount').textContent = 1 + S.peers.size;
}
function renderLobby() {
  const box = $('#lobby'); box.textContent = '';
  const card = (id, nick, st) => {
    const c = el('div', 'lcard'); c.dataset.speak = id;
    c.append(avatar(nick, id));
    const n = el('div', 'n', nick);
    if (st.deaf) n.prepend(icon('headoff')); else if (st.muted) n.prepend(icon('micoff'));
    c.append(n); return c;
  };
  box.append(card(S.myId || 'me', settings.nick, myState().state));
  for (const p of S.peers.values()) box.append(card(p.id, p.nick, p.state));
  if (!S.peers.size) box.append(el('div', 'hint', tr('alone')));
}

setInterval(() => {
  if ($('#room').hidden) return;
  const s = Math.max(0, Math.floor((Date.now() - S.since) / 1000));
  const h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, sec = s % 60;
  $('#timer').textContent = (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(sec).padStart(2, '0');
}, 1000);

// ------------------------------------------------------------------ settings dialog
async function fillDevices() {
  try {
    const devs = await navigator.mediaDevices.enumerateDevices();
    const fill = (sel, kind, cur) => {
      sel.textContent = '';
      const def = el('option', null, tr('default')); def.value = ''; sel.append(def);
      for (const d of devs.filter(d => d.kind === kind && d.deviceId && d.deviceId !== 'default')) {
        const o = el('option', null, d.label || kind); o.value = d.deviceId; sel.append(o);
      }
      sel.value = cur; if (sel.value !== cur) sel.value = '';
    };
    fill($('#micSel'), 'audioinput', settings.micId);
    fill($('#outSel'), 'audiooutput', settings.outId);
    $('#outField').hidden = !('setSinkId' in HTMLMediaElement.prototype);
  } catch { }
}
function openSettings() {
  $('#nsInput').checked = settings.ns; $('#qualSel').value = settings.quality; $('#echoSel').value = settings.antiEcho === 'off' ? 'off' : 'auto';
  $('#relaySet').checked = settings.relay; $('#soundsInput').checked = settings.sounds;
  fillDevices(); $('#settings').showModal();
}
function wireSettings() {
  $('#micSel').onchange = async e => {
    settings.micId = e.target.value; saveSettings();
    try { const st = await getMic(settings.micId); setMic(st.getAudioTracks()[0], st); } catch (err) { toast(tr('micErr') + err.message, true); }
  };
  $('#outSel').onchange = e => {
    settings.outId = e.target.value; saveSettings();
    for (const p of S.peers.values()) for (const a of p.audio.values()) a.setSinkId?.(settings.outId).catch(() => { });
  };
  $('#nsInput').onchange = async e => {
    settings.ns = e.target.checked; saveSettings();
    if (S.mic.track) { try { const st = await getMic(settings.micId); setMic(st.getAudioTracks()[0], st); } catch { } }
  };
  $('#qualSel').onchange = e => { settings.quality = e.target.value; saveSettings(); if (S.screen.stream) toast(tr('qualLater')); };
  $('#echoSel').onchange = e => { settings.antiEcho = e.target.value; saveSettings(); if (S.screen.stream) toast(tr('echoLater')); };
  $('#relaySet').onchange = e => { settings.relay = e.target.checked; saveSettings(); };
  $('#soundsInput').onchange = e => { settings.sounds = e.target.checked; saveSettings(); };
  $('#langSel').onchange = e => { settings.lang = e.target.value; saveSettings(); setLang(e.target.value); fillDevices(); };
}

// ------------------------------------------------------------------ boot
function parseRoute() {
  const m = location.pathname.match(/^\/r\/([A-Za-z0-9_-]{8,64})$/);
  if (!m) return null;
  const h = new URLSearchParams(location.hash.slice(1));
  return { room: m[1], k: h.get('k'), n: h.get('n') || '' };
}

async function enterRoom(route) {
  const raw = b64u.dec(route.k);
  if (raw.length !== 32) throw new Error('bad key');
  S.roomId = route.room; S.roomName = route.n.slice(0, 40);
  await setupKey(raw);

  S.ac = new (window.AudioContext || window.webkitAudioContext)();
  S.refBus = S.ac.createGain();
  S.ac.resume().catch(() => { });

  $('#landing').hidden = true; $('#room').hidden = false;
  $('#roomTitle').textContent = S.roomName || S.roomId.slice(0, 8);
  document.title = (S.roomName || tr('room')) + ' · побазарь)';
  $('#nickBar').value = settings.nick;
  renderAll();

  await initMic();
  connect();
}

/** landing tagline that depends on runtime state; re-evaluated on language switch */
function setLandingTag(fn) { const e = $('#landingTag'); delete e.dataset.th; e.textContent = fn(); landingTagFn = fn; }
let landingTagFn = null;
function setLang(l) {
  LANG = LANGS.includes(l) ? l : 'en';
  applyI18n();
  if (landingTagFn) $('#landingTag').textContent = landingTagFn();
  if (!$('#room').hidden) {
    document.title = (S.roomName || tr('room')) + ' · побазарь)';
    // tiles are cached; drop them so labels/tooltips are rebuilt in the new language
    for (const [, n] of tileNodes) n.node.remove();
    tileNodes.clear();
    renderAll();
  }
}

function boot() {
  hydrateIcons();
  wireSettings();
  setLang(settings.lang || ((navigator.languages || [navigator.language || '']).some(l => /^(ru|uk|be|kk)/i.test(l)) ? 'ru' : 'en'));
  document.querySelectorAll('#langSw [data-lang]').forEach(b => b.onclick = () => { settings.lang = b.dataset.lang; saveSettings(); setLang(b.dataset.lang); });
  const route = parseRoute();
  const nick = $('#nickInput');
  nick.value = settings.nick;
  $('#relayInput').checked = settings.relay;
  // relay ("hide my ip") is only possible when the server has a TURN relay configured
  $('#relayInput').closest('.check').hidden = true;
  $('#relaySet').closest('.check').hidden = true;
  fetch('/cfg').then(r => r.json()).then(c => {
    $('#relayInput').closest('.check').hidden = !c.relay;
    $('#relaySet').closest('.check').hidden = !c.relay;
  }).catch(() => { });

  if (route) {
    if (!route.k) { setLandingTag(() => tr('noKey')); $('#goBtn').hidden = true; nick.closest('.field').hidden = true; $('#roomNameField').hidden = true; return; }
    $('#roomNameField').hidden = true;
    setLandingTag(() => route.n ? tr('invitedTo', route.n.slice(0, 40)) : tr('invited'));
    $('#goBtn').dataset.t = 'join'; applyI18n();
  }
  nick.focus();
  const go = async () => {
    const n = nick.value.trim().slice(0, 32);
    if (!n) { nick.focus(); nick.style.borderColor = 'var(--bad)'; return; }
    settings.nick = n;
    if (!$('#relayInput').closest('.check').hidden) settings.relay = $('#relayInput').checked;
    saveSettings();
    let r = route;
    if (!r) {
      const name = $('#roomNameInput').value.trim().slice(0, 40);
      r = { room: b64u.enc(rnd(12)), k: b64u.enc(rnd(32)), n: name };
      const hash = '#k=' + r.k + (name ? '&n=' + encodeURIComponent(name) : '');
      history.replaceState(null, '', '/r/' + r.room + hash);
    }
    $('#goBtn').disabled = true;
    try { await enterRoom(r); }
    catch (e) { $('#goBtn').disabled = false; const er = $('#landingErr'); er.hidden = false; er.textContent = tr('badLink') + e.message; }
  };
  $('#goBtn').onclick = go;
  nick.onkeydown = e => { if (e.key === 'Enter') go(); };
  $('#roomNameInput').onkeydown = e => { if (e.key === 'Enter') go(); };

  // ---- room controls
  $('#muteBtn').onclick = toggleMute;
  $('#deafBtn').onclick = toggleDeaf;
  $('#camBtn').onclick = toggleCam;
  $('#shareBtn').onclick = toggleScreen;
  $('#settingsBtn').onclick = openSettings;
  $('#copyBtn').onclick = async () => {
    try { await navigator.clipboard.writeText(location.href); toast(tr('copied')); }
    catch { prompt(tr('copyPrompt'), location.href); }
  };
  $('#leaveBtn').onclick = () => {
    S.leaving = true;
    try { S.ws?.close(); } catch { }
    for (const p of S.peers.values()) p.close();
    [S.mic.raw, S.cam.stream, S.screen.stream].forEach(s => s?.getTracks().forEach(t => t.stop()));
    location.href = '/';
  };
  $('#chatToggle').onclick = () => { S.chatOpen = !S.chatOpen; $('#chatPanel').hidden = !S.chatOpen; $('#chatToggle').classList.toggle('on', S.chatOpen); if (S.chatOpen) { S.unread = 0; renderUnread(); $('#msgInput').focus(); } };
  $('#membersToggle').onclick = () => { S.membersOpen = !S.membersOpen; $('#membersPanel').hidden = !S.membersOpen; $('#membersToggle').classList.toggle('on', S.membersOpen); };
  if (matchMedia('(max-width: 760px)').matches) { S.chatOpen = false; S.membersOpen = false; $('#chatPanel').hidden = true; $('#membersPanel').hidden = true; }
  $('#chatToggle').classList.toggle('on', S.chatOpen); $('#membersToggle').classList.toggle('on', S.membersOpen);

  let nickT;
  $('#nickBar').oninput = e => {
    clearTimeout(nickT);
    nickT = setTimeout(() => { const v = e.target.value.trim().slice(0, 32); if (v && v !== settings.nick) { settings.nick = v; saveSettings(); broadcastState(); } }, 500);
  };

  const ta = $('#msgInput');
  ta.oninput = autoGrow;
  ta.onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendText(); } };
  ta.onpaste = e => { const fs = [...(e.clipboardData?.files || [])]; if (fs.length) { e.preventDefault(); sendFiles(fs); } };
  $('#sendBtn').onclick = sendText;
  $('#attachBtn').onclick = () => $('#fileInput').click();
  $('#fileInput').onchange = e => { sendFiles([...e.target.files]); e.target.value = ''; };
  const chat = $('#chatPanel');
  chat.ondragover = e => { e.preventDefault(); chat.classList.add('drop'); };
  chat.ondragleave = () => chat.classList.remove('drop');
  chat.ondrop = e => { e.preventDefault(); chat.classList.remove('drop'); sendFiles([...e.dataTransfer.files]); };

  document.addEventListener('keydown', e => {
    if ($('#room').hidden || !e.ctrlKey || !e.shiftKey) return;
    if (e.code === 'KeyM') { e.preventDefault(); toggleMute(); }
    if (e.code === 'KeyD') { e.preventDefault(); toggleDeaf(); }
  });
  navigator.mediaDevices?.addEventListener?.('devicechange', () => { if ($('#settings').open) fillDevices(); });
  window.addEventListener('beforeunload', () => { S.leaving = true; try { S.ws?.close(); } catch { } });
}

if (!window.isSecureContext) {
  document.addEventListener('DOMContentLoaded', () => setLandingTag(() => tr('needHttps')));
}
document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', boot) : boot();
