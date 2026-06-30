// REST client for the Kangal backend.
// All paths are relative — Vite proxies /api and /ws to localhost:8000 in dev.

export type ScanMode = 'passive' | 'active' | 'web_only' | 'network_only' | 'full_spectrum';

export interface ScanSummary {
  id: string;
  target: string;
  mode: ScanMode;
  status: 'queued' | 'running' | 'completed' | 'failed';
  current_stage: string | null;
  stats: Record<string, unknown>;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface AssetNode {
  id: string;
  type: string;
  value: string;
  parent_id: string | null;
  meta: Record<string, unknown>;
  discovered_by: string;
}

export interface GraphResponse {
  nodes: { id: string; type: 'data'; data: { label: string; type: string; discovered_by: string } }[];
  edges: { id: string; source: string; target: string }[];
  assets: AssetNode[];
}

export interface Finding {
  id: string;
  asset_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  vuln_class: string;
  title: string;
  evidence: Record<string, unknown>;
  created_at: string | null;
}

export interface ScanEvent {
  id: number;
  stage: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
  ts: string | null;
}

export interface IntelResult {
  id: string;
  scan_id: string;
  severity: string;
  vuln_class: string;
  title: string;
  evidence: Record<string, unknown>;
  score: number;
  source: string;
}

// ---------- toolbox ----------

export interface Tool {
  name: string;
  tier: 1 | 2;
  category: string;
  binary: string;
  timeout_default_s: number;
  rate_limit_per_min: number;
  requires_root: boolean;
  engagement_modes: string[];
  produces: string[];
  output_format: string;
}

export interface ToolCategory {
  category: string;
  tools: number;
  tiers: number[];
}

export interface ToolRunRequest {
  tool: string;
  target?: string;
  params?: Record<string, unknown>;
  scan_id?: string;
  timeout?: number;
  engagement_mode?: string;
}

export interface ToolRunResult {
  tool: string;
  target: string;
  scan_id: string;
  ok: boolean;
  returncode: number;
  timed_out: boolean;
  scope_violation: boolean;
  rate_limited: boolean;
  duration_s: number;
  raw_count: number;
  ruflo_pattern_id: string | null;
  error: string | null;
  parsed: Array<Record<string, unknown>>;
  stdout_excerpt: string;
  stderr_excerpt: string;
}

// ---------- engagement ----------

export interface Engagement {
  id: string;
  name: string;
  client: string;
  operator: string;
  scope_cidrs: string[];
  scope_domains: string[];
  excluded: string[];
  profile: string;
  start_at: number;
  end_at: number | null;
  destructive_allowed: boolean;
  status: string;
  scans_run: number;
  findings_count: number;
  created_at: number;
}

export interface EngagementCreate {
  name: string;
  client: string;
  operator: string;
  scope_cidrs: string[];
  scope_domains: string[];
  excluded?: string[];
  profile?: string;
  start_at?: number;
  end_at?: number;
  destructive_allowed?: boolean;
}

export interface ScopeCheckResult {
  target: string;
  in_scope: boolean;
  reason: string;
}

// ---------- red team events ----------

export interface MitreSummary {
  counts: Record<string, number>;
  techniques_total: number;
  attempts_total: number;
  success_total: number;
}

async function jsonOrThrow<T>(r: Response): Promise<T> {
  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`HTTP ${r.status}: ${txt || r.statusText}`);
  }
  return r.json() as Promise<T>;
}

// ---------- onboard (first-run wizard) ----------

export type OnboardPath = 'native' | 'wsl' | 'skip';

export interface OnboardDetected {
  platform: string | null;
  is_wsl: boolean;
  is_admin: boolean;
  capabilities_summary: Record<string, boolean>;
  recommendations: string[];
}

export interface OnboardState {
  current_step: string;
  completed_steps: string[];
  path_chosen: OnboardPath | null;
  consent_at: string | null;
  install_started: string[];
  install_completed: string[];
  completed: boolean;
  created_at: number;
  detected: OnboardDetected;
}

export interface OnboardInstallEntry {
  binary: string;
  install_id: string | null;
  status: 'started' | 'skipped' | string;
  reason?: string;
  command?: string[];
  command_str?: string;
}

export interface OnboardInstallResponse {
  installs: OnboardInstallEntry[];
  state: OnboardState;
}

export async function getOnboardState() {
  return jsonOrThrow<OnboardState>(await fetch('/api/onboard/state'));
}

export async function onboardChoosePath(path: OnboardPath) {
  return jsonOrThrow<OnboardState>(
    await fetch('/api/onboard/choose-path', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path }),
    })
  );
}

export async function onboardConsent(consent_text: string) {
  return jsonOrThrow<OnboardState>(
    await fetch('/api/onboard/consent', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ consent_text }),
    })
  );
}

export async function onboardInstall(binaries: string[]) {
  return jsonOrThrow<OnboardInstallResponse>(
    await fetch('/api/onboard/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ binaries }),
    })
  );
}

export async function onboardFinish() {
  return jsonOrThrow<OnboardState>(
    await fetch('/api/onboard/finish', { method: 'POST' })
  );
}

export interface SystemDiagBinary {
  name: string;
  present: boolean;
  path: string | null;
  version: string | null;
  install_cmd: string | null;
}

export interface SystemDiagHost {
  system: string;
  release: string;
  machine: string;
  python_version: string;
  is_wsl: boolean;
  is_admin: boolean;
  platform_id: string;
}

export interface SystemDiag {
  host: SystemDiagHost;
  binaries: Record<string, SystemDiagBinary>;
  summary: { present: number; total: number };
}

export async function getSystemDiag(): Promise<SystemDiag> {
  // 10s client-side timeout — diag probes run in parallel but a hung binary
  // shouldn't block the wizard forever.
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10_000);
  try {
    const r = await fetch('/api/system/diag', { signal: ctrl.signal });
    if (!r.ok) {
      throw new Error(`HTTP ${r.status}: ${await r.text()}`);
    }
    return (await r.json()) as SystemDiag;
  } finally {
    clearTimeout(t);
  }
}

export interface InstallStartResponse {
  install_id: string;
  binary: string;
  status: string;
  command: string[];
  command_str: string;
}

export interface InstallStatusResponse {
  install_id: string;
  binary: string;
  status: 'running' | 'ok' | 'failed';
  exit_code: number | null;
  duration_s: number | null;
  log: string[];
  error: string | null;
}

export async function startInstall(binary: string): Promise<InstallStartResponse> {
  return jsonOrThrow<InstallStartResponse>(
    await fetch(`/api/system/install/${encodeURIComponent(binary)}`, { method: 'POST' })
  );
}

export async function getInstallStatus(id: string): Promise<InstallStatusResponse> {
  return jsonOrThrow<InstallStatusResponse>(
    await fetch(`/api/system/install/${encodeURIComponent(id)}/status`)
  );
}

export async function getToolboxTools(): Promise<Tool[]> {
  // Wrapper that flattens api.toolboxTools() ({tools, count}) -> Tool[]
  const r = await api.toolboxTools({});
  return r.tools;
}

/** Download a single scan's markdown report. */
export async function getScanReport(scanId: string): Promise<Blob> {
  const r = await fetch(`/api/scan/${encodeURIComponent(scanId)}/report.md`);
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.blob();
}

export const api = {
  async startScan(target: string, mode: ScanMode = 'active') {
    return jsonOrThrow<{ scan_id: string; status: string; target: string; mode: ScanMode }>(
      await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode }),
      })
    );
  },

  async listScans() {
    return jsonOrThrow<ScanSummary[]>(await fetch('/api/scans'));
  },

  async getScan(id: string) {
    return jsonOrThrow<ScanSummary>(await fetch(`/api/scan/${id}`));
  },

  async getAssets(id: string) {
    return jsonOrThrow<GraphResponse>(await fetch(`/api/scan/${id}/assets`));
  },

  async getFindings(id: string) {
    return jsonOrThrow<Finding[]>(await fetch(`/api/scan/${id}/findings`));
  },

  async getEvents(id: string, since = 0) {
    return jsonOrThrow<ScanEvent[]>(await fetch(`/api/scan/${id}/events?since=${since}`));
  },

  async intelSearch(q: string) {
    return jsonOrThrow<{ query: string; results: IntelResult[]; count: number }>(
      await fetch(`/api/intel/search?q=${encodeURIComponent(q)}`)
    );
  },

  // ---------- toolbox ----------
  async toolboxSummary() {
    return jsonOrThrow<{ total: number; by_tier: Record<string, number>; by_category: Record<string, number>; registry_path: string | null }>(
      await fetch('/api/toolbox/summary')
    );
  },
  async toolboxTools(opts: { tier?: number; category?: string } = {}) {
    const qs = new URLSearchParams();
    if (opts.tier !== undefined) qs.set('tier', String(opts.tier));
    if (opts.category) qs.set('category', opts.category);
    const path = `/api/toolbox/tools${qs.toString() ? `?${qs}` : ''}`;
    return jsonOrThrow<{ tools: Tool[]; count: number }>(await fetch(path));
  },
  async toolboxCategories() {
    return jsonOrThrow<{ categories: ToolCategory[] }>(await fetch('/api/toolbox/categories'));
  },
  async toolboxExecute(req: ToolRunRequest) {
    return jsonOrThrow<ToolRunResult>(
      await fetch('/api/toolbox/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
    );
  },

  // ---------- engagement ----------
  async engagementCreate(req: EngagementCreate) {
    return jsonOrThrow<{ id: string; status: string }>(
      await fetch('/api/engagement', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
    );
  },
  async engagementList() {
    return jsonOrThrow<{ active: Record<string, Engagement>; count: number }>(
      await fetch('/api/engagement')
    );
  },
  async engagementGet(id: string) {
    return jsonOrThrow<Engagement>(await fetch(`/api/engagement/${id}`));
  },
  async engagementStop(id: string, reason = 'manual') {
    return jsonOrThrow<{ id: string; status: string }>(
      await fetch(`/api/engagement/${id}?reason=${encodeURIComponent(reason)}`, {
        method: 'DELETE',
      })
    );
  },
  async engagementPanic(id: string) {
    return jsonOrThrow<{ killed: boolean; engagement_id: string; killed_swarms: string[] }>(
      await fetch(`/api/engagement/${id}/panic`, { method: 'POST' })
    );
  },
  async engagementScopeCheck(target: string, engagement_id?: string) {
    return jsonOrThrow<ScopeCheckResult>(
      await fetch('/api/engagement/scope-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, engagement_id }),
      })
    );
  },

  // ---------- red team events ----------
  async exploitAttempt(req: {
    scan_id: string;
    target: string;
    technique: string;
    success: boolean;
    severity?: string;
    evidence?: Record<string, unknown>;
    mitre_technique?: string;
    payload_id?: string;
  }) {
    return jsonOrThrow<{ id: string; ok: boolean }>(
      await fetch('/api/redteam/exploit-attempt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
    );
  },
  async credentialDiscovered(req: {
    scan_id: string;
    target: string;
    service: string;
    username: string;
    secret_hash: string;
    source: string;
  }) {
    return jsonOrThrow<{ id: string; ok: boolean }>(
      await fetch('/api/redteam/credential', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
    );
  },
  async lateralPathIdentified(req: {
    scan_id: string;
    from_host: string;
    to_host: string;
    via_service: string;
    credential_ref?: string;
  }) {
    return jsonOrThrow<{ id: string; ok: boolean }>(
      await fetch('/api/redteam/lateral-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
    );
  },
  async mitreSummary() {
    return jsonOrThrow<MitreSummary>(await fetch('/api/redteam/mitre'));
  },

  // ---------- ruflo ----------
  async rufloSummary() {
    return jsonOrThrow<RufloSummary>(await fetch('/api/ruflo/summary'));
  },
  async rufloHooksStats() {
    return jsonOrThrow<RufloHooks>(await fetch('/api/ruflo/hooks/stats'));
  },
  async rufloMemoryStats() {
    return jsonOrThrow<RufloMemoryStats>(await fetch('/api/ruflo/memory/stats'));
  },
  async rufloMemorySearch(q: string, limit = 20) {
    return jsonOrThrow<{ query: string; results: IntelResult[]; count: number }>(
      await fetch(`/api/ruflo/memory/search?q=${encodeURIComponent(q)}&limit=${limit}`)
    );
  },
  async rufloPatterns(q?: string, limit = 50) {
    const path = q
      ? `/api/ruflo/patterns/search?q=${encodeURIComponent(q)}&limit=${limit}`
      : `/api/ruflo/patterns?limit=${limit}`;
    return jsonOrThrow<{ query: string; results: RufloPattern[]; count: number }>(
      await fetch(path)
    );
  },
  async rufloSwarmStatus() {
    return jsonOrThrow<RufloSwarmStatus>(await fetch('/api/ruflo/swarm/status'));
  },
  async rufloNeuralStatus() {
    return jsonOrThrow<RufloNeuralStatus>(await fetch('/api/ruflo/neural/status'));
  },
  async rufloAgents() {
    return jsonOrThrow<{ agents: RufloAgent[]; count: number }>(
      await fetch('/api/ruflo/agents')
    );
  },

  // ---------- interactive shell (PTY bash) ----------
  async createShellSession(cols = 120, rows = 32) {
    return jsonOrThrow<ShellSession>(
      await fetch('/api/shell/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cols, rows }),
      })
    );
  },
  async deleteShellSession(id: string) {
    return jsonOrThrow<{ session_id: string; status: string }>(
      await fetch(`/api/shell/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' })
    );
  },
  async listShellSessions() {
    return jsonOrThrow<{ sessions: ShellSession[]; count: number }>(
      await fetch('/api/shell/sessions')
    );
  },
};

export interface RufloSummary {
  hooks: RufloHooks;
  memory: RufloMemoryStats;
  swarms: RufloSwarmStatus;
  neural: RufloNeuralStatus;
  engagement: { active: Record<string, Engagement>; count: number };
  exploits: { total: number; successful: number };
  credentials: number;
  lateral_paths: number;
  persistence: number;
  c2_beacons: number;
  mitre: MitreSummary;
  agents: RufloAgent[];
}

export interface RufloHooks {
  pre: number;
  post: number;
  by_stage: Record<string, number>;
}

export interface RufloMemoryStats {
  stores: number;
  searches: number;
  findings_indexed: number;
  patterns_indexed: number;
}

export interface RufloPattern {
  ts: number;
  agent: string;
  target: string;
  outcome: string;
  confidence: number;
}

export interface RufloSwarm {
  scan_id: string;
  target: string;
  mode: string;
  started_at: number;
  status: string;
  topology: string;
  max_agents: number;
  agents: string[];
  finished_at?: number;
}

export interface RufloSwarmStatus {
  swarms: Record<string, RufloSwarm>;
  count: number;
}

export interface RufloNeuralTrajectory {
  ts: number;
  agent: string;
  scan_id: string;
  target: string;
  ok: boolean;
  duration_s: number;
}

export interface RufloNeuralAgentStats {
  ok: number;
  fail: number;
  n: number;
  avg_dur_s: number;
  success_rate: number;
}

export interface RufloNeuralStatus {
  trajectory_count: number;
  by_agent: Record<string, RufloNeuralAgentStats>;
  last_5: RufloNeuralTrajectory[];
}

export interface RufloAgent {
  id: string;
  type: string;
  capabilities: string[];
  cognitive_pattern: string;
}

// ---------- shell (PTY) ----------

export interface ShellSession {
  session_id: string;
  cols: number;
  rows: number;
  created_at: number;
  last_activity?: number;
  alive?: boolean;
}

// ---------- threat intel (live CVE + MITRE feed) ----------

export interface CVE {
  id: string;
  description: string;
  cvss_v3: { score: number; severity: string } | null;
  published: string;
  references: string[];
  source: string;
  stale: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  description: string;
  url: string;
  mitigations: string[];
  platforms: string[];
  data_sources: string[];
  source: string;
  stale: boolean;
}

export interface ThreatIntelFeed {
  recent_cves: CVE[];
  mitre_techniques: MitreTechnique[];
  generated_at: string;
  stale: boolean;
}

async function fetchJsonTimeout<T>(url: string, ms = 10_000): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
    return (await r.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

export async function getThreatIntelFeed(refresh = false): Promise<ThreatIntelFeed> {
  const qs = refresh ? '?refresh=true' : '';
  return fetchJsonTimeout<ThreatIntelFeed>(`/api/threat-intel/feed${qs}`, 10_000);
}

export async function getRecentCVEs(
  days = 7,
  severity = 'high'
): Promise<{ cves: CVE[] }> {
  const qs = new URLSearchParams({ days: String(days), severity });
  return fetchJsonTimeout<{ cves: CVE[] }>(
    `/api/threat-intel/recent-cves?${qs}`,
    10_000
  );
}

export async function getMitreTechnique(id: string): Promise<MitreTechnique> {
  return fetchJsonTimeout<MitreTechnique>(
    `/api/threat-intel/mitre/${encodeURIComponent(id)}`,
    10_000
  );
}

export async function searchMitre(q: string): Promise<{ results: MitreTechnique[] }> {
  const qs = new URLSearchParams({ q });
  return fetchJsonTimeout<{ results: MitreTechnique[] }>(
    `/api/threat-intel/mitre/search?${qs}`,
    10_000
  );
}