import { useEffect, useRef, useState } from 'react';
import { Crosshair, Brain, Box, HelpCircle, Search, Terminal, Activity, Wrench, FileText, Code, AlertTriangle } from 'lucide-react';
import { useStore, STAGES } from '@/lib/store';
import { api, type ScanMode } from '@/lib/api';
import { ScanStream } from '@/lib/ws';

import { TargetInput } from '@/components/TargetInput';
import { StageProgress } from '@/components/StageProgress';
import { LiveTerminal } from '@/components/LiveTerminal';
import { ShellPanel } from '@/components/ShellPanel';
import { PreShellPanel } from '@/components/PreShellPanel';
import { AssetGraph } from '@/components/AssetGraph';
import { GraphDetailPanel } from '@/components/GraphDetailPanel';
import { FindingsPanel } from '@/components/FindingsPanel';
import { ScanHistory } from '@/components/ScanHistory';
import { IntelSearch } from '@/components/IntelSearch';
import { RufloStatus } from '@/components/RufloStatus';
import { RufloDetail, type DetailKind } from '@/components/RufloDetail';
import { ToolboxStatus, ToolInventory } from '@/components/ToolboxStatus';
import { EngagementPanel } from '@/components/EngagementPanel';
import { MitreHeatmap } from '@/components/MitreHeatmap';
import { OnboardModal, useOnboardFlag } from '@/components/OnboardModal';
import { Logo } from '@/components/Logo';
import { DiagnosticsModal } from '@/components/DiagnosticsModal';
import { ToolManagerView } from '@/components/views/ToolManagerView';
import { ReportsView } from '@/components/views/ReportsView';
import { CLIView } from '@/components/views/CLIView';
import { ThreatIntelView } from '@/components/views/ThreatIntelView';

function App() {
  const {
    scans,
    selectedScanId,
    currentScan,
    graph,
    findings,
    terminal,
    shellOpen,
    preShellOpen,
    toggleShell,
    togglePreShell,
    setPreShellOpen,
    selectedAsset,
    selectedAssetId,
    setSelectedAssetId,
    graphSearch,
    setGraphSearch,
    setScans,
    selectScan,
    setCurrentScan,
    setGraph,
    setFindings,
    appendTerminal,
    resetTerminal,
  } = useStore();

  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<'graph' | 'intel' | 'toolbox' | 'tool_manager' | 'reports' | 'cli' | 'threat_intel'>('graph');
  const [rufloDetail, setRufloDetail] = useState<DetailKind | null>(null);
  const streamRef = useRef<ScanStream | null>(null);
  const diagModalOpen = useStore((s) => s.diagModalOpen);
  const toggleDiagModal = useStore((s) => s.toggleDiagModal);

  const [onboardOpen, reopenOnboard, setOnboardOpen] = useOnboardFlag();

  // Initial scan list + poll every 5s
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const list = await api.listScans();
        if (!alive) return;
        setScans(list);
      } catch {
        /* backend not up — ignore */
      }
    };
    tick();
    const t = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [setScans]);

  // When selected scan changes, load its full snapshot
  useEffect(() => {
    if (!selectedScanId) {
      setCurrentScan(null);
      setGraph(null);
      setFindings([]);
      return;
    }
    let alive = true;
    (async () => {
      try {
        const [s, g, f, ev] = await Promise.all([
          api.getScan(selectedScanId),
          api.getAssets(selectedScanId),
          api.getFindings(selectedScanId),
          api.getEvents(selectedScanId, 0),
        ]);
        if (!alive) return;
        setCurrentScan(s);
        setGraph(g);
        setFindings(f);
        resetTerminal();
        // Replay historical events into terminal
        for (const e of ev) {
          appendTerminal({ stage: e.stage, level: e.level, message: e.message, ts: e.ts });
        }
      } catch (err) {
        console.error('Failed to load scan', err);
      }
    })();
    return () => {
      alive = false;
    };
  }, [selectedScanId, setCurrentScan, setGraph, setFindings, appendTerminal, resetTerminal]);

  // WebSocket: live events for the selected scan
  useEffect(() => {
    if (!selectedScanId) {
      streamRef.current?.close();
      streamRef.current = null;
      return;
    }
    const stream = new ScanStream(selectedScanId);
    stream.connect();
    streamRef.current = stream;
    const handler = (ev: { kind: string; stage?: string; level?: string; message?: string; ts?: string | null }) => {
      if (ev.kind === 'event' && ev.stage && ev.message) {
        appendTerminal({
          stage: ev.stage,
          level: ev.level || 'info',
          message: ev.message,
          ts: ev.ts || null,
        });
      }
    };
    stream.on(handler);

    // Also poll current scan + assets/findings while scan is running
    const interval = setInterval(async () => {
      if (!selectedScanId) return;
      try {
        const [s, g, f] = await Promise.all([
          api.getScan(selectedScanId),
          api.getAssets(selectedScanId),
          api.getFindings(selectedScanId),
        ]);
        setCurrentScan(s);
        setGraph(g);
        setFindings(f);
        if (s.status === 'completed' || s.status === 'failed') {
          setBusy(false);
        }
      } catch {
        /* ignore transient */
      }
    }, 2000);

    return () => {
      stream.off(handler);
      stream.close();
      streamRef.current = null;
      clearInterval(interval);
    };
  }, [selectedScanId, appendTerminal, setCurrentScan, setGraph, setFindings]);

  const onEngage = async (target: string, mode: ScanMode) => {
    setBusy(true);
    try {
      const r = await api.startScan(target, mode);
      // Refresh list and select the new one
      const list = await api.listScans();
      setScans(list);
      selectScan(r.scan_id);
    } catch (err) {
      console.error('Engage failed', err);
      setBusy(false);
    }
  };

  const agentStats = (() => {
    const s = (currentScan?.stats || {}) as Record<string, { ok?: boolean; duration_s?: number; error?: string }>;
    return s;
  })();

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-border px-6 py-3">
        <div className="flex items-center gap-3">
          <Logo />
          <div>
            <h1 className="text-xl font-bold text-white tracking-widest">
              KANGAL <span className="text-primary">DASHBOARD</span>
            </h1>
            <p className="text-[10px] text-gray-500 font-mono uppercase">
              Multi-Stage Threat Intelligence &amp; Recon Orchestration
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-gray-400">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary"></span>
            </span>
            SYSTEM ONLINE
          </div>
          <div className="text-gray-600">|</div>
          <div className="text-gray-400">
            {scans.length} SCAN{scans.length !== 1 ? 'S' : ''} ON RECORD
          </div>
          <div className="text-gray-600">|</div>
          <ToolboxStatus compact />
          <div className="text-gray-600">|</div>
          <RufloStatus onOpenDetail={(k: DetailKind) => setRufloDetail(k)} />
          <div className="text-gray-600">|</div>
          <button
            onClick={toggleDiagModal}
            title="Diagnostics — capability matrix + installer"
            className="text-gray-400 hover:text-primary"
          >
            <Activity className="w-4 h-4" />
          </button>
          <button
            onClick={reopenOnboard}
            title="Show the welcome tour"
            className="text-gray-400 hover:text-primary"
          >
            <HelpCircle className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* 3-Column Body */}
      <main className="flex-1 grid grid-cols-12 gap-3 p-3 min-h-0">
        {/* Left column: scan history + intel search */}
        <aside className="col-span-3 flex flex-col gap-3 min-h-0">
          <div className="flex-[2] min-h-0 border border-border rounded-lg bg-surface/40 overflow-hidden">
            <ScanHistory
              scans={scans}
              selectedId={selectedScanId}
              onSelect={(id) => selectScan(id)}
              onRefresh={async () => {
                const list = await api.listScans();
                setScans(list);
              }}
            />
          </div>
          <div className="flex-1 min-h-0 border border-border rounded-lg bg-surface/40 overflow-hidden">
            <IntelSearch />
          </div>
        </aside>

        {/* Center column: target input, stage progress, terminal, findings */}
        <section className="col-span-6 flex flex-col gap-3 min-h-0">
          <div className="border border-border rounded-lg bg-surface/40 p-4">
            <TargetInput onEngage={onEngage} busy={busy} />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-1 border border-border rounded-lg bg-surface/40 p-3">
              <StageProgress
                currentStage={currentScan?.current_stage ?? null}
                status={currentScan?.status ?? 'queued'}
                agentStats={agentStats as Record<string, { ok: boolean; error?: string; duration_s?: number }>}
              />
            </div>
            <div className="col-span-2 border border-border rounded-lg bg-surface/40 p-3">
              <div className="text-xs font-mono text-gray-400 uppercase mb-2">Scan Summary</div>
              {currentScan ? (
                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-gray-500">target</span>
                    <span className="text-gray-200 truncate ml-2" title={currentScan.target}>
                      {currentScan.target}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">mode</span>
                    <span className="text-primary">{currentScan.mode}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">status</span>
                    <span
                      className={
                        currentScan.status === 'completed'
                          ? 'text-green-500'
                          : currentScan.status === 'failed'
                            ? 'text-destructive'
                            : currentScan.status === 'running'
                              ? 'text-primary'
                              : 'text-gray-400'
                      }
                    >
                      {currentScan.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">stage</span>
                    <span className="text-gray-300">
                      {currentScan.current_stage
                        ? STAGES.find((s) => s === currentScan.current_stage) ||
                          currentScan.current_stage
                        : '—'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">assets</span>
                    <span className="text-gray-300">{graph?.assets.length ?? 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">findings</span>
                    <span
                      className={
                        findings.length > 0 ? 'text-yellow-500' : 'text-gray-300'
                      }
                    >
                      {findings.length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">started</span>
                    <span className="text-gray-400">
                      {currentScan.started_at
                        ? new Date(currentScan.started_at).toLocaleTimeString()
                        : '—'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">finished</span>
                    <span className="text-gray-400">
                      {currentScan.finished_at
                        ? new Date(currentScan.finished_at).toLocaleTimeString()
                        : '—'}
                    </span>
                  </div>
                  {currentScan.error && (
                    <div className="text-destructive mt-2 text-[10px] break-all">
                      {currentScan.error}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-xs font-mono text-gray-600">
                  Select a scan from history or ENGAGE a new target.
                </div>
              )}
            </div>
          </div>
          <div className="flex-1 min-h-[260px] flex flex-col gap-2">
            <div className="flex items-center gap-1.5 px-1">
              <button
                onClick={() => {
                  if (shellOpen) toggleShell();
                }}
                className={`text-[10px] font-mono px-2 py-1 rounded ${
                  !shellOpen
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-surface text-gray-400 border border-border'
                }`}
                title="Show the live scan event stream"
              >
                <Crosshair className="w-3 h-3 inline mr-1" /> LIVE STREAM
              </button>
              <button
                onClick={() => {
                  if (shellOpen) toggleShell();
                  else if (preShellOpen) togglePreShell();
                  else togglePreShell();
                }}
                className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                  shellOpen || preShellOpen
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-surface text-gray-400 border border-border'
                }`}
                title="Open an interactive bash in the backend container"
              >
                <Terminal className="w-3 h-3" /> SHELL
              </button>
            </div>
            <div className="flex-1 min-h-0">
              {shellOpen ? (
                <ShellPanel
                  onClose={() => toggleShell()}
                />
              ) : preShellOpen ? (
                <PreShellPanel
                  onLaunch={() => {
                    setPreShellOpen(false);
                    toggleShell();
                  }}
                  onClose={() => togglePreShell()}
                />
              ) : (
                <LiveTerminal lines={terminal} title="Live Recon Stream" />
              )}
            </div>
          </div>
          <div className="h-72 border border-border rounded-lg bg-surface/40 overflow-hidden">
            <FindingsPanel findings={findings} />
          </div>
        </section>

        {/* Right column: asset graph / intel / toolbox */}
        <aside className="col-span-3 flex flex-col gap-3 min-h-0">
          <div className="flex items-center gap-1 px-1 flex-wrap">
            <button
              onClick={() => setView('graph')}
              className={`text-[10px] font-mono px-2 py-1 rounded ${
                view === 'graph'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
            >
              ASSET GRAPH
            </button>
            <button
              onClick={() => setView('intel')}
              className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                view === 'intel'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
            >
              <Brain className="w-3 h-3" /> INTEL
            </button>
            <button
              onClick={() => setView('toolbox')}
              className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                view === 'toolbox'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
            >
              <Box className="w-3 h-3" /> TOOLBOX
            </button>
            <button
              onClick={() => setView('tool_manager')}
              className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                view === 'tool_manager'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
              title="Tool Manager — registry browser + installer"
            >
              <Wrench className="w-3 h-3" /> TOOL MGR
            </button>
            <button
              onClick={() => setView('reports')}
              className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                view === 'reports'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
              title="Reports — scan history + markdown export"
            >
              <FileText className="w-3 h-3" /> REPORTS
            </button>
            <button
              onClick={() => setView('cli')}
              className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                view === 'cli'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
              title="Kangal CLI install snippet"
            >
              <Code className="w-3 h-3" /> CLI
            </button>
            <button
              onClick={() => setView('threat_intel')}
              className={`text-[10px] font-mono px-2 py-1 rounded flex items-center gap-1 ${
                view === 'threat_intel'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-surface text-gray-400 border border-border'
              }`}
              title="Threat Intel — live CVE feed + MITRE ATT&CK browser"
            >
              <AlertTriangle className="w-3 h-3" /> THREAT
            </button>
          </div>
          <EngagementPanel />
          {view === 'graph' && (
            <div className="px-1">
              <div className="flex items-center gap-1.5 bg-surface/60 border border-border rounded px-2 py-1">
                <Search className="w-3 h-3 text-gray-500 shrink-0" />
                <input
                  type="text"
                  value={graphSearch}
                  onChange={(e) => setGraphSearch(e.target.value)}
                  placeholder="search graph (port, host, type)…"
                  className="flex-1 bg-transparent outline-none text-[11px] font-mono text-gray-200 placeholder:text-gray-600"
                />
                {graphSearch && (
                  <button
                    onClick={() => setGraphSearch('')}
                    className="text-[10px] text-gray-500 hover:text-gray-300"
                    title="Clear"
                  >
                    ✕
                  </button>
                )}
              </div>
            </div>
          )}
          <div className="flex-1 min-h-0 overflow-y-auto space-y-3 pr-1">
            {view === 'graph' ? (
              <div className="h-full min-h-[300px] border border-border rounded-lg bg-surface/40 overflow-hidden relative">
                <AssetGraph
                  assets={graph?.assets ?? []}
                  nodes={graph?.nodes ?? []}
                  edges={graph?.edges ?? []}
                  scanId={selectedScanId ?? undefined}
                  search={graphSearch}
                  selectedAssetId={selectedAssetId}
                  onSelectAsset={setSelectedAssetId}
                />
              </div>
            ) : view === 'intel' ? (
              <div className="h-full min-h-[300px] border border-border rounded-lg bg-surface/40 overflow-hidden">
                <IntelSearch />
              </div>
            ) : view === 'toolbox' ? (
              <>
                <ToolboxStatus />
                <ToolInventory />
              </>
            ) : view === 'tool_manager' ? (
              <div className="h-full min-h-[300px] border border-border rounded-lg bg-surface/40 overflow-hidden">
                <ToolManagerView />
              </div>
            ) : view === 'reports' ? (
              <div className="h-full min-h-[300px] border border-border rounded-lg bg-surface/40 overflow-hidden">
                <ReportsView />
              </div>
            ) : view === 'cli' ? (
              <div className="h-full min-h-[300px] border border-border rounded-lg bg-surface/40 overflow-hidden">
                <CLIView />
              </div>
            ) : view === 'threat_intel' ? (
              <div className="h-full min-h-[300px] border border-border rounded-lg bg-surface/40 overflow-hidden">
                <ThreatIntelView />
              </div>
            ) : null}
          </div>
          <MitreHeatmap />
        </aside>
      </main>

      <RufloDetail kind={rufloDetail} onClose={() => setRufloDetail(null)} />
      <GraphDetailPanel
        asset={selectedAsset()}
        findings={findings}
        onClose={() => setSelectedAssetId(null)}
      />
      <OnboardModal open={onboardOpen} onOpenChange={setOnboardOpen} />
      <DiagnosticsModal open={diagModalOpen} onClose={toggleDiagModal} />
    </div>
  );
}

export default App;
