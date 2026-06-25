// DiagnosticsModal — full-screen modal hosting DiagnosticsView.
//
// Reached from the Activity icon in the dashboard header. ESC or X closes.

import { useEffect } from 'react';
import { X, Activity } from 'lucide-react';

import { DiagnosticsView } from '@/components/views/DiagnosticsView';

interface DiagnosticsModalProps {
  open: boolean;
  onClose: () => void;
}

export function DiagnosticsModal({ open, onClose }: DiagnosticsModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-stretch justify-stretch p-4">
      <div className="flex-1 flex flex-col border border-border rounded-lg bg-[#0a0a0a] shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-primary" />
            <span className="text-sm font-mono text-white tracking-widest uppercase">
              Diagnostics
            </span>
            <span className="text-[10px] font-mono text-gray-500">
              capability matrix + installer
            </span>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="text-gray-500 hover:text-gray-200"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="flex-1 min-h-0 overflow-hidden">
          <DiagnosticsView embedded />
        </div>
      </div>
    </div>
  );
}
