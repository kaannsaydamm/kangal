import { useEffect, useState } from 'react';
import { Crosshair } from 'lucide-react';
import { api, type MitreSummary } from '@/lib/api';

const TECHNIQUE_NAMES: Record<string, string> = {
  T1190: 'Exploit Public-Facing Application',
  T1189: 'Drive-by Compromise',
  T1059: 'Command and Scripting Interpreter',
  T1083: 'File and Directory Discovery',
  T1110: 'Brute Force',
  T1552: 'Unsecured Credentials',
  T1078: 'Valid Accounts',
};

export function MitreHeatmap() {
  const [m, setM] = useState<MitreSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await api.mitreSummary();
        if (!alive) return;
        setM(r);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const t = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (err) return <div className="text-[10px] font-mono text-yellow-500">MITRE: {err.slice(0, 50)}</div>;
  if (!m) return <div className="text-[10px] font-mono text-gray-500">MITRE: …</div>;

  const entries = Object.entries(m.counts).sort((a, b) => b[1] - a[1]);
  const max = entries.reduce((mx, [, c]) => Math.max(mx, c), 1);

  return (
    <div className="border border-border rounded-lg bg-surface/40 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono text-gray-400 uppercase flex items-center gap-1.5">
          <Crosshair className="w-3.5 h-3.5 text-red-400" />
          MITRE ATT&amp;CK
        </div>
        <div className="text-[10px] font-mono text-gray-500">
          {m.techniques_total} techniques · {m.attempts_total} attempts · {m.success_total} successful
        </div>
      </div>
      {entries.length === 0 ? (
        <div className="text-[10px] font-mono text-gray-600">no technique events recorded yet</div>
      ) : (
        <div className="space-y-1">
          {entries.map(([tid, count]) => {
            const intensity = Math.min(1, count / max);
            const bg = `rgba(239, 68, 68, ${0.15 + intensity * 0.6})`;
            return (
              <div
                key={tid}
                className="flex items-center justify-between px-2 py-1 rounded"
                style={{ background: bg }}
              >
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono font-bold text-red-100">{tid}</span>
                  <span className="text-[10px] font-mono text-red-100 truncate">
                    {TECHNIQUE_NAMES[tid] || 'unknown'}
                  </span>
                </div>
                <span className="text-[10px] font-mono font-bold text-white">{count}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
