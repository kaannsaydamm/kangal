import { Loader2, CheckCircle2, XCircle, Clock, RefreshCw } from 'lucide-react';
import type { ScanSummary } from '@/lib/api';

interface ScanHistoryProps {
  scans: ScanSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onRefresh: () => void;
}

const STATUS_STYLES: Record<ScanSummary['status'], { icon: typeof Loader2; color: string; label: string }> = {
  queued: { icon: Clock, color: 'text-gray-400', label: 'QUEUED' },
  running: { icon: Loader2, color: 'text-primary animate-spin', label: 'RUNNING' },
  completed: { icon: CheckCircle2, color: 'text-green-500', label: 'DONE' },
  failed: { icon: XCircle, color: 'text-destructive', label: 'FAILED' },
};

export function ScanHistory({ scans, selectedId, onSelect, onRefresh }: ScanHistoryProps) {
  return (
    <div className="h-full flex flex-col">
      <div className="px-3 py-2 border-b border-border flex items-center justify-between">
        <span className="text-xs font-mono text-gray-400 uppercase">Scan History</span>
        <button
          onClick={onRefresh}
          className="p-1 hover:bg-surface rounded text-gray-500 hover:text-primary"
          title="Refresh"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>
      <div className="flex-1 overflow-auto">
        {scans.length === 0 ? (
          <div className="p-4 text-xs font-mono text-gray-600 text-center">No scans yet.</div>
        ) : (
          <ul>
            {scans.map((s) => {
              const style = STATUS_STYLES[s.status];
              const Icon = style.icon;
              const isSel = s.id === selectedId;
              return (
                <li
                  key={s.id}
                  onClick={() => onSelect(s.id)}
                  className={`px-3 py-2 border-b border-border/40 cursor-pointer hover:bg-surface ${
                    isSel ? 'bg-primary/10 border-l-2 border-l-primary' : ''
                  }`}
                >
                  <div className="flex items-center gap-2 mb-0.5">
                    <Icon className={`w-3 h-3 ${style.color}`} />
                    <span className={`text-[10px] font-bold ${style.color}`}>{style.label}</span>
                    <span className="text-[9px] font-mono text-gray-600 ml-auto">{s.mode}</span>
                  </div>
                  <div className="text-xs font-mono text-gray-200 truncate" title={s.target}>
                    {s.target}
                  </div>
                  <div className="text-[9px] text-gray-600 mt-0.5">
                    {s.started_at ? new Date(s.started_at).toLocaleString() : '—'}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}