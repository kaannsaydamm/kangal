import { useState } from 'react';
import { Brain, Search, Loader2 } from 'lucide-react';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { api, type IntelResult } from '@/lib/api';

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
  info: 'text-gray-400',
};

export function IntelSearch() {
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<IntelResult[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const search = async () => {
    if (!q.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await api.intelSearch(q);
      setResults(r.results);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 py-2 border-b border-border flex items-center gap-2">
        <Brain className="w-3.5 h-3.5 text-primary" />
        <span className="text-xs font-mono text-gray-400 uppercase">Threat Intel</span>
      </div>
      <div className="p-3 space-y-2">
        <div className="flex gap-1.5">
          <Input
            placeholder="search past findings…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && search()}
            className="text-xs font-mono bg-surface"
          />
          <Button size="sm" onClick={search} disabled={busy || !q.trim()}>
            {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
          </Button>
        </div>
        {err && <div className="text-[10px] text-destructive font-mono">{err}</div>}
        {results.length > 0 && (
          <div className="text-[10px] text-gray-500 font-mono">
            {results.length} match{results.length !== 1 ? 'es' : ''}
          </div>
        )}
      </div>
      <div className="flex-1 overflow-auto px-3 pb-3 space-y-1.5">
        {results.map((r) => (
          <div
            key={r.id}
            className="border border-border/60 rounded p-2 bg-background/50 text-[10px] font-mono"
          >
            <div className="flex items-center gap-1.5 mb-0.5">
              <span className={`font-bold ${SEV_COLORS[r.severity] || 'text-gray-400'}`}>
                [{r.severity.toUpperCase()}]
              </span>
              <span className="text-gray-500">{r.vuln_class}</span>
            </div>
            <div className="text-gray-200">{r.title}</div>
            {r.evidence?.url ? (
              <div className="text-gray-500 truncate mt-0.5">{String(r.evidence.url)}</div>
            ) : r.evidence?.value ? (
              <div className="text-gray-500 truncate mt-0.5">{String(r.evidence.value)}</div>
            ) : null}
          </div>
        ))}
        {results.length === 0 && q && !busy && (
          <div className="text-[10px] font-mono text-gray-600 text-center py-4">
            No matches.
          </div>
        )}
      </div>
    </div>
  );
}