import { CheckCircle2, Circle, Loader2, AlertCircle } from 'lucide-react';
import { STAGES, type StageName } from '@/lib/store';

interface StageProgressProps {
  currentStage: string | null;
  status: string;
  agentStats?: Record<string, { ok: boolean; error?: string; duration_s?: number }>;
}

const STAGE_LABELS: Record<StageName, string> = {
  subdomain: 'Subdomain Discovery',
  dns: 'DNS Resolve',
  http_probe: 'HTTP Probe',
  portscan: 'Port Scan',
  tech: 'Tech Fingerprint',
  pathscan: 'Path Scan',
  vuln: 'Vuln Correlator',
};

export function StageProgress({ currentStage, status, agentStats }: StageProgressProps) {
  return (
    <div className="space-y-2">
      <div className="text-xs font-mono text-gray-400 uppercase">Pipeline</div>
      <div className="grid grid-cols-1 gap-1">
        {STAGES.map((stage) => {
          const stats = agentStats?.[stage];
          const isCurrent = currentStage === stage && status === 'running';
          const isDone = !!stats;
          const isFailed = stats && !stats.ok;

          let Icon = Circle;
          let cls = 'text-gray-600';
          if (isFailed) {
            Icon = AlertCircle;
            cls = 'text-destructive';
          } else if (isCurrent) {
            Icon = Loader2;
            cls = 'text-primary animate-spin';
          } else if (isDone) {
            Icon = CheckCircle2;
            cls = 'text-green-500';
          }

          return (
            <div
              key={stage}
              className="flex items-center justify-between text-xs font-mono py-1 px-2 rounded border border-border/50 bg-background/30"
            >
              <div className="flex items-center gap-2">
                <Icon className={`w-3.5 h-3.5 ${cls}`} />
                <span className={isCurrent ? 'text-primary' : isDone ? 'text-gray-300' : 'text-gray-500'}>
                  {STAGE_LABELS[stage]}
                </span>
              </div>
              {stats && (
                <span className="text-[10px] text-gray-600">
                  {stats.duration_s?.toFixed(2)}s
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}