# Kangal Overhaul Plan

## Phase A: Backend capabilities (parallel, 3 agents)
- A1: System diagnostics endpoint
- A2: Tools registry expansion (38 → 80+)
- A3: Install command executor

## Phase B: Onboard wizard overhaul (parallel, 2 agents)
- B1: Backend onboard state
- B2: Frontend OnboardModal v2 (5 steps)

## Phase C: Pre-shell diagnostic panel
- C1: PreShellPanel component (capability gate)

## Phase D: kangal-cli
- D1: Click-based CLI tool with scan/intel/engagement/shell/tool/onboard subcommands

## Phase E: New UI pages
- E1: Sidebar + router + 7 pages (Recon/Toolbox/Intel/Diagnostics/Reports/Shell/Onboard)

## Phase F: E2E + ralph loop
- F1: Update tests, loop until PASS

## Critical files
- backend/app/main.py
- backend/tools-registry.json
- backend/app/{diagnostics,installer,onboard}.py (new)
- frontend/src/components/OnboardModal.tsx (rewrite)
- frontend/src/components/PreShellPanel.tsx (new)
- frontend/src/components/Sidebar.tsx (new)
- frontend/src/router.tsx (new)
- frontend/src/pages/*.tsx (new)
- cli/kangal/main.py (new)
- tests/e2e/kangal.spec.mjs (extend)

## Success criteria
- ≥ 80 tools
- Onboard v2 with detect + consent + install
- Pre-shell capability matrix
- kangal-cli functional
- 7 new pages
- All E2E tests pass
