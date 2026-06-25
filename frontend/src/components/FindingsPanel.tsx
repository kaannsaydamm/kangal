import { useState } from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldCheck, ShieldX, ChevronRight, ChevronDown, ExternalLink } from 'lucide-react';
import type { Finding } from '@/lib/api';

const SEV_ORDER: Finding['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_STYLES: Record<Finding['severity'], { color: string; bg: string; border: string; icon: typeof AlertCircle; label: string }> = {
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', icon: ShieldX, label: 'CRITICAL' },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: AlertCircle, label: 'HIGH' },
  medium: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', icon: AlertTriangle, label: 'MEDIUM' },
  low: { color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/30', icon: AlertTriangle, label: 'LOW' },
  info: { color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/30', icon: Info, label: 'INFO' },
};

interface FindingsPanelProps {
  findings: Finding[];
}

export function FindingsPanel({ findings }: FindingsPanelProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<Finding['severity'] | 'all'>('all');

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filtered = filter === 'all' ? findings : findings.filter((f) => f.severity === filter);
  const counts = SEV_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length;
    return acc;
  }, {});

  if (findings.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-600 font-mono text-xs">
        <div className="text-center">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-green-500 opacity-70" />
          <div>No findings yet.</div>
          <div className="text-[10px] mt-1">Vulnerabilities and observations will appear here.</div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="px-3 py-2 border-b border-border flex items-center gap-2 flex-wrap">
        <span className="text-xs font-mono text-gray-400 uppercase mr-2">Filter:</span>
        <button
          onClick={() => setFilter('all')}
          className={`text-[10px] font-mono px-2 py-0.5 rounded ${
            filter === 'all' ? 'bg-primary text-primary-foreground' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          ALL ({findings.length})
        </button>
        {SEV_ORDER.map((s) =>
          counts[s] ? (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                filter === s ? SEV_STYLES[s].bg + ' ' + SEV_STYLES[s].color + ' border ' + SEV_STYLES[s].border : 'bg-surface text-gray-400 border border-border'
              }`}
            >
              {SEV_STYLES[s].label} ({counts[s]})
            </button>
          ) : null
        )}
      </div>
      <div className="flex-1 overflow-auto divide-y divide-border/50">
        {filtered.map((f) => {
          const s = SEV_STYLES[f.severity];
          const Icon = s.icon;
          const isOpen = expanded.has(f.id);
          // MITRE technique id can live in evidence.mitre_technique or top-level evidence.mitre_technique
          const mitreId = (f.evidence?.mitre_technique as string | undefined) ?? null;
          const mitreUrl = mitreId
            ? `https://attack.mitre.org/techniques/${mitreId.replace('.', '/')}`
            : null;
          return (
            <div key={f.id} className={`p-3 ${s.bg} border-l-2 ${s.border.replace('border-', 'border-l-')}`}>
              <div
                className="flex items-start gap-2 cursor-pointer"
                onClick={() => toggle(f.id)}
              >
                {isOpen ? <ChevronDown className="w-3.5 h-3.5 mt-0.5 text-gray-500" /> : <ChevronRight className="w-3.5 h-3.5 mt-0.5 text-gray-500" />}
                <Icon className={`w-4 h-4 mt-0.5 ${s.color}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                    <span className={`text-[10px] font-bold ${s.color}`}>{s.label}</span>
                    <span className="text-[10px] font-mono text-gray-500">{f.vuln_class}</span>
                    {mitreId && mitreUrl && (
                      <a
                        href={mitreUrl}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        title={`MITRE ATT&CK — ${mitreId}`}
                        className="inline-flex items-center gap-0.5 text-[9px] font-mono px-1 py-0.5 rounded border border-primary/40 bg-primary/10 text-primary hover:bg-primary/20"
                      >
                        MITRE {mitreId} <ExternalLink className="w-2 h-2" />
                      </a>
                    )}
                  </div>
                  <div className="text-xs text-gray-200">{f.title}</div>
                </div>
              </div>
              {isOpen && (
                <div className="mt-2 ml-5 text-[10px] font-mono text-gray-400 bg-background/60 rounded p-2 border border-border/50">
                  <pre className="whitespace-pre-wrap break-all">
                    {JSON.stringify(f.evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}