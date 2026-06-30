// Bidirectional WebSocket stream for the live PTY shell.
//
// Wire protocol matches the backend (text frames, JSON, base64 payload):
//   client → server:
//     {kind:"data",   data:"<b64>"}     # keystrokes
//     {kind:"resize", cols:N, rows:N}    # xterm fit
//     {kind:"ping"}                      # liveness
//   server → client:
//     {kind:"open",   session_id, cols, rows}
//     {kind:"out",    data:"<b64>"}      # PTY stdout
//     {kind:"exit",   code}
//     {kind:"error",  message}
//     {kind:"pong"}
//
// This is the bidirectional cousin of `ws.ts#ScanStream` — same shape
// (handlers, open/close, reconnect), but with `send()` and an outbound
// `lastResize` cache so a reconnect can replay the last terminal size.

export type ServerFrame =
  | { kind: 'open'; session_id: string; cols: number; rows: number }
  | { kind: 'out'; data: string } // base64
  | { kind: 'exit'; code: number }
  | { kind: 'error'; message: string }
  | { kind: 'pong' };

export type ClientFrame =
  | { kind: 'data'; data: string } // base64
  | { kind: 'resize'; cols: number; rows: number }
  | { kind: 'ping' };

export type BiHandler = (f: ServerFrame) => void;

export class BiStream {
  private ws: WebSocket | null = null;
  private handlers: BiHandler[] = [];
  private closed = false;
  private url: string;
  private lastResize: { cols: number; rows: number } | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;

  constructor(sessionId: string) {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    this.url = `${proto}://${window.location.host}/ws/shell/${sessionId}`;
  }

  connect() {
    this.closed = false;
    const ws = new WebSocket(this.url);
    this.ws = ws;
    ws.onopen = () => {
      // Replay last known size so the server-side PTY matches xterm.
      if (this.lastResize) {
        this.resize(this.lastResize.cols, this.lastResize.rows);
      }
      // Liveness ping every 30s keeps the reaper from collecting us
      // and detects dead sockets quickly.
      if (this.pingTimer) clearInterval(this.pingTimer);
      this.pingTimer = setInterval(() => this.ping(), 30000);
    };
    ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as ServerFrame;
        this.handlers.forEach((h) => h(ev));
      } catch {
        // ignore malformed frames
      }
    };
    ws.onclose = () => {
      if (this.pingTimer) {
        clearInterval(this.pingTimer);
        this.pingTimer = null;
      }
      if (this.closed) return;
      // Reconnect after 1s — the PTY survives, so the operator
      // usually sees a brief "Reconnecting…" frame in xterm.
      setTimeout(() => this.connect(), 1000);
    };
    ws.onerror = () => {
      // onclose handles reconnect
    };
  }

  on(h: BiHandler) {
    this.handlers.push(h);
  }

  off(h: BiHandler) {
    this.handlers = this.handlers.filter((x) => x !== h);
  }

  send(frame: ClientFrame) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    try {
      this.ws.send(JSON.stringify(frame));
      return true;
    } catch {
      return false;
    }
  }

  /** Send raw bytes (e.g. xterm keystrokes) as a {kind:"data", data:<b64>} frame. */
  writeBytes(b: Uint8Array) {
    // btoa accepts strings; convert bytes to a binary string first.
    let bin = '';
    for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
    return this.send({ kind: 'data', data: btoa(bin) });
  }

  resize(cols: number, rows: number) {
    this.lastResize = { cols, rows };
    return this.send({ kind: 'resize', cols, rows });
  }

  ping() {
    return this.send({ kind: 'ping' });
  }

  close() {
    this.closed = true;
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
    try {
      this.ws?.close();
    } catch {
      // ignore
    }
  }
}
