import { useState } from 'react';
import { Crosshair, Zap, Eye, Globe, Network, Skull } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import type { ScanMode } from '@/lib/api';

interface TargetInputProps {
  onEngage: (target: string, mode: ScanMode) => void;
  busy: boolean;
}

const MODES: { id: ScanMode; label: string; sub: string; icon: React.ReactNode; color: string }[] = [
  {
    id: 'passive',
    label: 'PASSIVE',
    sub: 'OSINT only · subfinder / amass / harvester',
    icon: <Eye className="w-3.5 h-3.5" />,
    color: 'cyan',
  },
  {
    id: 'active',
    label: 'ACTIVE',
    sub: '+ ports / HTTP / paths / vuln',
    icon: <Zap className="w-3.5 h-3.5" />,
    color: 'primary',
  },
  {
    id: 'web_only',
    label: 'WEB',
    sub: '+ sqlmap / dalfox / xsstrike / nikto',
    icon: <Globe className="w-3.5 h-3.5" />,
    color: 'orange',
  },
  {
    id: 'network_only',
    label: 'NET',
    sub: '+ smb / ssh / nxc / bloodhound',
    icon: <Network className="w-3.5 h-3.5" />,
    color: 'purple',
  },
  {
    id: 'full_spectrum',
    label: 'FULL',
    sub: 'all of the above + exploit + cloud',
    icon: <Skull className="w-3.5 h-3.5" />,
    color: 'red',
  },
];

function modeClasses(id: ScanMode, current: ScanMode, color: string) {
  if (id === current) {
    return `border-${color} bg-${color}/10 text-${color}`;
  }
  return 'border-border bg-surface text-gray-400 hover:border-primary/30';
}

export function TargetInput({ onEngage, busy }: TargetInputProps) {
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<ScanMode>('active');

  const submit = () => {
    const t = target.trim();
    if (!t) return;
    onEngage(t, mode);
  };

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <label className="text-[10px] font-mono text-gray-400 uppercase flex items-center gap-2">
          <Crosshair className="w-3 h-3" /> Target
        </label>
        <div className="flex gap-2">
          <Input
            placeholder="evilcorp.com · 45.33.32.156 · repo://github.com/x/y"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
            disabled={busy}
            className="font-mono text-gray-200 border-border bg-surface text-xs"
          />
          <Button onClick={submit} disabled={busy || !target.trim()}>
            {busy ? 'SCANNING…' : 'ENGAGE'}
          </Button>
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-[10px] font-mono text-gray-400 uppercase">Engagement Mode</label>
        <div className="grid grid-cols-5 gap-1.5">
          {MODES.map((m) => {
            const active = mode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => setMode(m.id)}
                disabled={busy}
                title={m.sub}
                className={`flex flex-col items-start gap-0.5 p-1.5 rounded border text-[10px] font-mono transition ${
                  active
                    ? m.color === 'red'
                      ? 'border-red-500 bg-red-500/10 text-red-300'
                      : m.color === 'orange'
                        ? 'border-orange-500 bg-orange-500/10 text-orange-300'
                        : m.color === 'purple'
                          ? 'border-purple-500 bg-purple-500/10 text-purple-300'
                          : m.color === 'cyan'
                            ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                            : 'border-primary bg-primary/10 text-primary'
                    : 'border-border bg-surface text-gray-400 hover:border-primary/30'
                }`}
              >
                <div className="flex items-center gap-1 font-bold">
                  {m.icon}
                  {m.label}
                </div>
                <div className="text-[9px] text-gray-500 truncate w-full text-left">
                  {m.sub}
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
