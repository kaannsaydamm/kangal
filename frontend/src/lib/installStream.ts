// WebSocket helper that streams a background install's log lines.
// Wire protocol (text frames, JSON) — see backend main.py ws_install():
//   server -> client:
//     {kind:"log",   line:"..."}
//     {kind:"done",  status:"ok"|"failed", exit_code:N}
//     {kind:"error", message:"..."}
//
// Exposes a tiny EventTarget so React components can subscribe to
// 'log' / 'done' / 'error' without juggling raw sockets themselves.

export interface InstallLogEvent {
  line: string;
}
export interface InstallDoneEvent {
  status: 'ok' | 'failed';
  exit_code: number | null;
}
export interface InstallErrorEvent {
  message: string;
}

export class InstallStream extends EventTarget {
  private ws: WebSocket | null = null;
  private url: string;
  private closed = false;
  private log: string[] = [];

  constructor(installId: string) {
    super();
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    this.url = `${proto}://${window.location.host}/ws/install/${encodeURIComponent(installId)}`;
  }

  connect(): void {
    if (this.closed) return;
    this.ws = new WebSocket(this.url);
    this.ws.onmessage = (m) => {
      let payload: { kind?: string; line?: string; status?: string; exit_code?: number | null; message?: string } | null = null;
      try {
        payload = JSON.parse(m.data) as typeof payload;
      } catch {
        // ignore non-JSON frames
        return;
      }
      if (!payload || !payload.kind) return;
      if (payload.kind === 'log' && typeof payload.line === 'string') {
        this.log.push(payload.line);
        this.dispatchEvent(new CustomEvent<InstallLogEvent>('log', { detail: { line: payload.line } }));
      } else if (payload.kind === 'done') {
        this.dispatchEvent(
          new CustomEvent<InstallDoneEvent>('done', {
            detail: {
              status: (payload.status === 'ok' ? 'ok' : 'failed'),
              exit_code: typeof payload.exit_code === 'number' ? payload.exit_code : null,
            },
          })
        );
        this.close();
      } else if (payload.kind === 'error') {
        this.dispatchEvent(
          new CustomEvent<InstallErrorEvent>('error', {
            detail: { message: payload.message || 'install error' },
          })
        );
        this.close();
      }
    };
    this.ws.onclose = () => {
      // No auto-reconnect — installs are short-lived, reconnection would
      // create duplicate job streams on the backend side.
    };
    this.ws.onerror = () => {
      this.dispatchEvent(
        new CustomEvent<InstallErrorEvent>('error', { detail: { message: 'websocket error' } })
      );
    };
  }

  /** All log lines received so far (for late subscribers). */
  getLog(): string[] {
    return [...this.log];
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.ws?.close();
    } catch {
      // ignore
    }
    this.ws = null;
  }
}