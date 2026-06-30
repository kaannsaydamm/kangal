// Per-scan WebSocket helper. Reconnects on close.

export interface StreamEvent {
  kind: 'event' | 'error';
  stage?: string;
  level?: 'info' | 'warn' | 'error' | 'success';
  message?: string;
  ts?: string | null;
  replay?: boolean;
}

export type EventHandler = (e: StreamEvent) => void;

export class ScanStream {
  private ws: WebSocket | null = null;
  private handlers: EventHandler[] = [];
  private url: string;
  private closed = false;

  constructor(scanId: string) {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    this.url = `${proto}://${window.location.host}/ws/scan/${scanId}`;
  }

  connect() {
    this.closed = false;
    this.ws = new WebSocket(this.url);
    this.ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as StreamEvent;
        this.handlers.forEach((h) => h(ev));
      } catch {
        // ignore non-JSON lines (legacy support)
      }
    };
    this.ws.onclose = () => {
      if (this.closed) return;
      // Reconnect after 2s
      setTimeout(() => this.connect(), 2000);
    };
    this.ws.onerror = () => {
      // let onclose handle reconnection
    };
  }

  on(h: EventHandler) {
    this.handlers.push(h);
  }

  off(h: EventHandler) {
    this.handlers = this.handlers.filter((x) => x !== h);
  }

  close() {
    this.closed = true;
    this.ws?.close();
  }
}