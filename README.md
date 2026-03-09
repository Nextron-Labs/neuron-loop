# Neuron-Loop

A multi-model code review and fix orchestrator. Sends code to competing AI reviewers in parallel, triages findings by cross-model agreement, applies fixes via a coder model, then verifies the diff with an independent model — looping until convergence or max iterations.

Zero external dependencies beyond Python 3.6+ stdlib (PyYAML optional). Uses OpenClaw's `models.json` for provider credentials — no API keys in this repo.

## How It Works

```
                    ┌──────────────────────────┐
                    │     Pre-review Tests      │ (optional)
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   Parallel Code Review    │
                    │                           │
                    │  T1: Sonnet OR GPT-5.4    │ ← alternates per iteration
                    │  T2: GLM-5 + OR Auto      │ ← always run (cheap/free)
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │     Triage & Dedup        │
                    │                           │
                    │  • Fingerprint findings   │
                    │  • Cluster by similarity  │
                    │  • Apply gate rules       │
                    │  • Skip already-addressed │
                    └────────────┬─────────────┘
                                 │
                        actionable findings?
                       ╱                    ╲
                    NO                       YES
                     │                        │
              ✅ Converged          ┌─────────▼─────────┐
                                    │   Coder (Opus)     │
                                    │                    │
                                    │  SEARCH/REPLACE    │
                                    │  blocks applied    │
                                    └─────────┬─────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  Diff Verification │
                                    │  (other T1 model)  │
                                    │                    │
                                    │  BAD → revert      │
                                    │  GOOD → continue   │
                                    └─────────┬─────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  Post-fix Tests    │
                                    │                    │
                                    │  FAIL → revert to  │
                                    │  last good state   │
                                    └─────────┬─────────┘
                                              │
                                         next iteration
```

### Key Design Decisions

**Alternating T1 reviewers.** Rather than running both expensive models every iteration, odd iterations use Sonnet and even use GPT-5.4. The idle T1 model verifies the diff instead — so both models contribute every round, but at half the review cost.

**Tiered gate rules.** Not all findings are equal. Two models agreeing on the same issue → auto-fix. A single T1 model → fix (with care). A single T2 model → skip unless CRITICAL. This filters out the ~30% false positive rate from cheaper models.

**Cross-iteration dedup.** Findings are fingerprinted (Jaccard similarity on normalized tokens) and tracked across iterations. If the coder already addressed a finding, it won't be re-sent even if a reviewer flags it again.

**Revert-on-failure.** The system maintains a "last known good" snapshot. If post-fix tests fail or the diff verifier rejects changes, files revert automatically. The coder never builds on broken state.

**SEARCH/REPLACE patches.** The coder returns surgical `<<<SEARCH ... >>>REPLACE ... <<<END` blocks rather than full files. This keeps diffs small, reviewable, and less likely to silently drop code. Falls back to full-file extraction if no blocks are found.

## Quick Start

```bash
# Copy and edit config
cp config.example.yaml config.yaml

# Review only (no fixes)
python3 neuron-loop.py \
  --task task.md \
  --files src/collector.lua \
  --review-only

# Full loop with tests
python3 neuron-loop.py \
  --task task.md \
  --files src/collector.lua \
  --test "bash tests/run.sh"

# Override coder model
python3 neuron-loop.py \
  --task task.md \
  --files script.py \
  --coder-model openai/gpt-5.4
```

## Model Tiers

| Tier | Role | Default Models | Notes |
|------|------|----------------|-------|
| Coder | Writes fixes | Claude Opus 4.6 | Strongest available model |
| T1 | Deep review | Sonnet 4.6, GPT-5.4 | Alternate per iteration, cross-verify diffs |
| T2 | Sweep | GLM-5, OpenRouter Auto | Cheap/free, broader coverage, ~30% FP rate |

### Gate Rules

| Condition | Action |
|-----------|--------|
| 2+ models agree on same finding | Auto-fix |
| 1 T1 model flags it | Fix (with care) |
| 1 T2 model, severity CRITICAL | Fix |
| 1 T2 model, non-CRITICAL | Skip |
| Already addressed in prior iteration | Skip |

## Configuration

Copy `config.example.yaml` to `config.yaml`. Models are referenced by provider/model ID — credentials come from OpenClaw's `~/.openclaw/agents/main/agent/models.json`.

```yaml
tiers:
  coder:
    model: "anthropic/claude-opus-4-6"
  tier1:
    - provider: anthropic
      model: "claude-sonnet-4-6"
      label: "sonnet"
    - provider: openai
      model: "gpt-5.4"
      label: "gpt54"
  tier2:
    - provider: ollama-cloud
      model: "glm-5:cloud"
      label: "glm5"

gate:
  auto_fix_threshold: 2          # N+ models agree → auto-fix
  tier1_single_action: "fix"     # 1 T1 model → fix
  tier2_single_action: "skip_unless_critical"

loop:
  max_iterations: 10
  convergence_threshold: 0       # Stop at ≤N findings

test:
  command: "bash tests/run.sh"   # Exit 0 = pass
  before_review: true
  after_fix: true
```

## Run Output

Each run creates a timestamped directory under `runs/`:

```
runs/2026-03-08_121057_task-lua-full/
  config.json              — frozen config (secrets redacted)
  task.md                  — task prompt copy
  events.jsonl             — structured event log
  neuron-loop.log          — human-readable log
  summary.json             — final stats
  files/
    original/              — pre-run file snapshots
    iter-01/               — files after iteration 1
  reviews/
    iter-01/
      sonnet-raw.md        — raw reviewer response
      sonnet-findings.json — extracted findings
  triage/
    iter-01.json           — deduplicated + gated findings
  fixes/
    iter-01-request.md     — prompt sent to coder
    iter-01-response.md    — coder's response
  verification/
    iter-01-gpt54.md       — diff verification response
  tests/
    iter-01-pre.txt        — pre-review test output
    iter-01-post.txt       — post-fix test output
```

## CLI Options

```
--task TASK.md          Task/context file (required)
--files FILE [FILE...]  Files to review (required)
--config CONFIG         Config file (default: config.yaml)
--test CMD              Test command (exit 0 = pass)
--standards FILE        Standards file for comparison
--output DIR            Output directory (default: ./runs)
--max-iter N            Max iterations (default: 10)
--review-only           Review only, no fix loop
--coder-model P/M       Override coder model (provider/model)
--skip-tier1            Skip T1 reviewers
--skip-tier2            Skip T2 reviewers
--quiet                 Minimal output
--version               Show version
```

## Requirements

- Python 3.6+
- OpenClaw with configured providers in `models.json`
- PyYAML (optional — falls back to built-in defaults)
