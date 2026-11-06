// Untrusted rendezvous relay for the two-party chat.
//
// SECURITY MODEL — this process is NOT trusted, and clients must treat it as
// hostile. It can read every signaling message it forwards (room ids, public
// keys, challenges, signatures and SDP bodies, including DTLS fingerprints),
// so nothing here may be described as opaque or encrypted forwarding: there is
// no encryption at this layer, and end-to-end confidentiality applies only to
// the WebRTC data channel that the peers establish afterwards (DTLS). The
// integrity of the negotiated session comes from the clients' own signatures
// over the transcript, never from this server.
//
// Behaviour: it stores nothing, keeps no history, and forwards a message only
// while both peers of a room are connected. A third join into a room is
// rejected. Logs record event names, room ids and byte counts only — never
// message contents.

import { WebSocketServer } from 'ws';
import { createServer } from 'node:http';

export const ROOM_MAX = 2;
export const MAX_PAYLOAD_BYTES = 64 * 1024;
export const MAX_MESSAGE_BYTES = 96 * 1024;
export const MAX_RELAYS_PER_WINDOW = 120;
export const RATE_WINDOW_MS = 10_000;

const ROOM_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

export function createRelay({ log = () => {} } = {}) {
  /** @type {Map<string, Set<object>>} */
  const rooms = new Map();

  function roomOf(ws) {
    return ws.__room ?? null;
  }

  function leave(ws) {
    const room = roomOf(ws);
    if (room === null) return;
    const members = rooms.get(room);
    ws.__room = null;
    if (!members) return;
    members.delete(ws);
    for (const peer of members) {
      send(peer, { type: 'peer-left' });
    }
    if (members.size === 0) rooms.delete(room);
    log({ event: 'leave', room });
  }

  function send(ws, message) {
    if (ws.readyState !== ws.OPEN) return false;
    ws.send(JSON.stringify(message));
    return true;
  }

  function fail(ws, code, fatal = false) {
    send(ws, { type: 'error', code });
    if (fatal) ws.close(1008, code);
  }

  function handleJoin(ws, msg) {
    if (roomOf(ws) !== null) return fail(ws, 'ALREADY_JOINED');
    const room = msg.room;
    if (typeof room !== 'string' || !ROOM_PATTERN.test(room)) {
      return fail(ws, 'BAD_ROOM', true);
    }
    const members = rooms.get(room) ?? new Set();
    if (members.size >= ROOM_MAX) return fail(ws, 'ROOM_FULL', true);

    members.add(ws);
    rooms.set(room, members);
    ws.__room = room;

    const peerPresent = members.size === ROOM_MAX;
    send(ws, { type: 'joined', room, peerPresent });
    for (const peer of members) {
      if (peer !== ws) send(peer, { type: 'peer-joined' });
    }
    log({ event: 'join', room, size: members.size });
  }

  function withinRate(ws, now) {
    if (now - ws.__windowStart >= RATE_WINDOW_MS) {
      ws.__windowStart = now;
      ws.__count = 0;
    }
    ws.__count += 1;
    return ws.__count <= MAX_RELAYS_PER_WINDOW;
  }

  function handleRelay(ws, msg) {
    const room = roomOf(ws);
    if (room === null) return fail(ws, 'NOT_JOINED', true);
    if (!withinRate(ws, Date.now())) return fail(ws, 'RATE_LIMITED', true);

    const payload = msg.payload;
    if (typeof payload !== 'string') return fail(ws, 'BAD_PAYLOAD');
    if (Buffer.byteLength(payload, 'utf8') > MAX_PAYLOAD_BYTES) {
      return fail(ws, 'PAYLOAD_TOO_LARGE', true);
    }

    const members = rooms.get(room);
    if (!members) return fail(ws, 'NOT_JOINED', true);
    let delivered = 0;
    for (const peer of members) {
      if (peer !== ws) delivered += send(peer, { type: 'relay', payload }) ? 1 : 0;
    }
    // Nothing is buffered: an absent peer means the payload is dropped.
    send(ws, { type: 'relay-status', delivered });
    log({ event: 'relay', room, delivered, bytes: Buffer.byteLength(payload, 'utf8') });
  }

  function handleMessage(ws, raw) {
    if (typeof raw !== 'string' && !Buffer.isBuffer(raw)) return fail(ws, 'BAD_MESSAGE', true);
    if (raw.length > MAX_MESSAGE_BYTES) return fail(ws, 'MESSAGE_TOO_LARGE', true);

    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return fail(ws, 'BAD_JSON', true);
    }
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      return fail(ws, 'BAD_MESSAGE', true);
    }

    switch (msg.type) {
      case 'join':
        return handleJoin(ws, msg);
      case 'relay':
        return handleRelay(ws, msg);
      case 'leave':
        leave(ws);
        return send(ws, { type: 'left' });
      case 'ping':
        return send(ws, { type: 'pong' });
      default:
        return fail(ws, 'UNKNOWN_TYPE');
    }
  }

  function attach(ws) {
    ws.__room = null;
    ws.__windowStart = Date.now();
    ws.__count = 0;
    ws.on('message', (raw) => handleMessage(ws, raw));
    ws.on('close', () => leave(ws));
    ws.on('error', () => leave(ws));
  }

  return { attach, rooms, _leave: leave };
}

export function startServer({ port = Number(process.env.PORT ?? 8787), host = process.env.HOST ?? '127.0.0.1', log = console.log } = {}) {
  const relay = createRelay({
    log: (entry) => log(JSON.stringify(entry)),
  });
  const server = createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, rooms: relay.rooms.size }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  // maxPayload is enforced by `ws` while the frame is still being received, so
  // an oversized frame is dropped at the transport layer instead of being
  // buffered whole and checked afterwards. Without it the default is 100 MiB:
  // memory would be consumed before the MAX_MESSAGE_BYTES check ever runs.
  // A frame over the limit makes `ws` close the sender with code 1009, which
  // only affects that connection; the server keeps serving everyone else.
  const wss = new WebSocketServer({ server, maxPayload: MAX_MESSAGE_BYTES });
  wss.on('connection', (ws) => relay.attach(ws));
  server.listen(port, host, () => log(JSON.stringify({ event: 'listening', host, port })));
  return { server, wss, relay };
}

if (process.env.PORT || process.env.START_RELAY === '1' || (process.argv[1] && process.argv[1].endsWith('server.js'))) {
  startServer({ host: process.env.HOST ?? '0.0.0.0' });
}
