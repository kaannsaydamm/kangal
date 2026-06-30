// Zustand store: currently-selected scan + the running scan's stream state.

import { create } from 'zustand';
import type { AssetNode, Finding, GraphResponse, ScanEvent, ScanSummary } from './api';

export const STAGES = ['subdomain', 'dns', 'http_probe', 'portscan', 'tech', 'pathscan', 'vuln'] as const;
export type StageName = (typeof STAGES)[number];

export interface TerminalLine {
  stage: string;
  level: string;
  message: string;
  ts?: string | null;
}

interface UIState {
  /** When true, the center slot shows the PTY shell instead of the live stream. */
  shellOpen: boolean;
  /** When true, the center slot shows the PreShellPanel capability gate. */
  preShellOpen: boolean;
  /** The asset currently selected in the right-column graph (drives the drawer). */
  selectedAssetId: string | null;
  /** Free-text search string used to dim non-matching graph nodes. */
  graphSearch: string;
  /** Modal open flag for the first-run / `?`-button onboard tour. */
  onboardOpen: boolean;
  /** Full-screen modal: capability matrix + per-binary installer. */
  diagModalOpen: boolean;
  /** Right-column view: threat_intel is one of the selectable tabs. */
  threatIntelTab: 'cves' | 'mitre';

  setShellOpen: (v: boolean) => void;
  toggleShell: () => void;
  setPreShellOpen: (v: boolean) => void;
  togglePreShell: () => void;
  setSelectedAssetId: (id: string | null) => void;
  setGraphSearch: (q: string) => void;
  setOnboardOpen: (v: boolean) => void;
  setDiagModalOpen: (v: boolean) => void;
  toggleDiagModal: () => void;
  setThreatIntelTab: (t: 'cves' | 'mitre') => void;
}

interface State extends UIState {
  scans: ScanSummary[];
  selectedScanId: string | null;
  currentScan: ScanSummary | null;
  graph: GraphResponse | null;
  findings: Finding[];
  events: ScanEvent[];
  terminal: TerminalLine[];

  setScans: (s: ScanSummary[]) => void;
  selectScan: (id: string | null) => void;
  setCurrentScan: (s: ScanSummary | null) => void;
  setGraph: (g: GraphResponse | null) => void;
  setFindings: (f: Finding[]) => void;
  appendEvent: (e: ScanEvent) => void;
  setEvents: (e: ScanEvent[]) => void;
  appendTerminal: (line: TerminalLine) => void;
  resetTerminal: () => void;

  /** Convenience selectors. */
  selectedAsset: () => AssetNode | null;
}

export const useStore = create<State>((set, get) => ({
  scans: [],
  selectedScanId: null,
  currentScan: null,
  graph: null,
  findings: [],
  events: [],
  terminal: [],

  // ui
  shellOpen: false,
  preShellOpen: false,
  selectedAssetId: null,
  graphSearch: '',
  onboardOpen: false,
  diagModalOpen: false,
  threatIntelTab: 'cves',

  setShellOpen: (v) => set({ shellOpen: v }),
  toggleShell: () => set((s) => ({ shellOpen: !s.shellOpen })),
  setPreShellOpen: (v) => set({ preShellOpen: v }),
  togglePreShell: () => set((s) => ({ preShellOpen: !s.preShellOpen })),
  setSelectedAssetId: (id) => set({ selectedAssetId: id }),
  setGraphSearch: (q) => set({ graphSearch: q }),
  setOnboardOpen: (v) => set({ onboardOpen: v }),
  setDiagModalOpen: (v) => set({ diagModalOpen: v }),
  toggleDiagModal: () => set((s) => ({ diagModalOpen: !s.diagModalOpen })),
  setThreatIntelTab: (t) => set({ threatIntelTab: t }),

  setScans: (scans) => set({ scans }),
  selectScan: (id) => set({ selectedScanId: id, selectedAssetId: null, graphSearch: '' }),
  setCurrentScan: (currentScan) => set({ currentScan }),
  setGraph: (graph) => set({ graph }),
  setFindings: (findings) => set({ findings }),
  appendEvent: (e) => set((s) => ({ events: [...s.events, e] })),
  setEvents: (events) => set({ events }),
  appendTerminal: (line) =>
    set((s) => ({ terminal: [...s.terminal.slice(-999), line] })),
  resetTerminal: () => set({ terminal: [], events: [] }),

  selectedAsset: () => {
    const s = get();
    if (!s.selectedAssetId) return null;
    return s.graph?.assets.find((a) => a.id === s.selectedAssetId) ?? null;
  },
}));