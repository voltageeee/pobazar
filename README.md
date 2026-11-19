# побазарь)

голосовые комнаты с демкой экрана (со звуком) и чатом. всё со сквозным шифрованием, без аккаунтов, логов и телеметрии.

voice rooms with screen share (with sound) and chat. end-to-end encrypted, no accounts, no logs, no telemetry.

---

## ru

- создаёшь комнату, вводишь ник, кидаешь ссылку — всё
- ключ комнаты живёт только во фрагменте ссылки (`#k=…`) и никогда не уходит на сервер
- сигналинг и чат: aes-256-gcm (hkdf-sha256), сервер пересылает только зашифрованные байты
- медиа: webrtc p2p (dtls-srtp), отпечатки dtls ходят внутри зашифрованного сигналинга, поэтому сервер не может встать посередине
- демка со стерео-звуком 160 кбит/с и антиэхо (голоса собеседников вычитаются из звука всего экрана)
- чат без лимита в 1024 байта, файлы до 8 мб
- до 16 человек в комнате, опциональный turn-relay, чтобы скрыть ip

```
cargo build --release
./target/release/hush            # http на 127.0.0.1:8095, ставь за прокси/туннель с https
```

переменные окружения:

| | |
|---|---|
| `LISTEN` | адрес, по умолчанию `127.0.0.1:8095` |
| `DOMAIN` | включает встроенный https через let's encrypt |
| `STUN_URLS` | stun-серверы через запятую |
| `TURN_SECRET`, `TURN_URLS` | свой coturn (`use-auth-secret`) |
| `CF_TURN_KEY_ID`, `CF_TURN_TOKEN` | cloudflare realtime turn |

## en

- create a room, pick a nickname, share the link — that's it
- the room key lives only in the link fragment (`#k=…`) and never reaches the server
- signaling and chat: aes-256-gcm (hkdf-sha256), the server relays opaque bytes only
- media: webrtc p2p (dtls-srtp), dtls fingerprints travel inside the encrypted signaling, so the server can't mitm
- screen share with 160 kbps stereo audio and anti-echo (others' voices are subtracted from whole-screen audio)
- no 1024-byte chat limit, files up to 8 mb
- up to 16 people per room, optional turn relay to hide your ip

```
cargo build --release
./target/release/hush            # http on 127.0.0.1:8095, put it behind an https proxy/tunnel
```

environment:

| | |
|---|---|
| `LISTEN` | bind address, default `127.0.0.1:8095` |
| `DOMAIN` | enables built-in https via let's encrypt |
| `STUN_URLS` | comma-separated stun servers |
| `TURN_SECRET`, `TURN_URLS` | your own coturn (`use-auth-secret`) |
| `CF_TURN_KEY_ID`, `CF_TURN_TOKEN` | cloudflare realtime turn |
