# Neuron-Loop

A multi-model code review and fix orchestrator. Implements a tight coding ↔ review ↔ test loop with tiered model architecture.

## Architecture

```
┌─────────┐     ┌──────────────────────┐     ┌──────────┐
│  Coder  │────▶│   Parallel Reviews   │────▶│  Triage  │
│(Sonnet) │     │ T1: Sonnet + GPT-5.4 │     │  (gate   │
└─────────┘     │ T2: GLM-5 + OR Auto  │     │  rules)  │
     ▲          └──────────────────────┘     └────┬─────┘
     │                                            │
     │         actionable findings?               │
     └──────────────YES───────────────────────────┘
               NO ──▶ ✅ converged
```

## Quick Start

```bash
# Review only (no fixes)
python3 neuron-loop.py \
  --task TASK.md \
  --files thunderstorm-collector.lua \
  --review-only

# Full loop with tests
python3 neuron-loop.py \
  --task TASK.md \
  --files thunderstorm-collector.lua \
  --test "bash scripts/tests/e2e/run_e2e.sh"

# Custom config
python3 neuron-loop.py \
  --task TASK.md \
  --files script.py \
  --config my-config.yaml \
  --max-iter 5
```

## Model Tiers

### Tier 1 — Primary Reviewers
Deep review, independent analysis. Cross-referenced for confidence.
- **Sonnet 4.6**: Strong on language-specific gotchas, PS/Perl idioms
- **GPT-5.4**: Systematic consistency checks, cross-script parity

### Tier 2 — Sweep Models
Cheaper/free, broader coverage. Higher false positive rate (~30%).
- **GLM-5** (Ollama Cloud): Free, catches obvious issues
- **OpenRouter Auto**: Free tier, diverse model routing

### Gate Rules
| Condition | Action |
|-----------|--------|
| 2+ models agree | Auto-fix |
| 1 Tier 1 model | Fix (assess carefully) |
| 1 Tier 2 model, CRITICAL | Fix |
| 1 Tier 2 model, non-CRITICAL | Skip |

## Configuration

See `config.yaml` for full options. Key settings:

```yaml
tiers:
  coder:
    model: "anthropic/claude-sonnet-4-6"
  tier1:
    - provider: anthropic
      model: "claude-sonnet-4-6"
      label: "sonnet"
    - provider: openai
      model: "gpt-5.4"
      label: "gpt54"

gate:
  auto_fix_threshold: 2
  tier1_single_action: "fix"
  tier2_single_action: "skip_unless_critical"

loop:
  max_iterations: 10
  convergence_threshold: 0
```

## Output

Each iteration produces:
- `output/iteration-NN.md` — Triage report
- `output/iter-NN-{model}-raw.md` — Raw review responses
- `output/iter-NN-coder-response.md` — Coder fix response

## Options

```
--task TASK.md         Context/task description (required)
--files FILE [FILE]    Files to review (required)
--config CONFIG        Config file (default: config.yaml)
--test CMD             Test command (exit 0 = pass)
--standards FILE       Standards file for comparison
--output DIR           Output directory
--max-iter N           Max iterations
--review-only          Review only, no fix loop
--coder-model P/M      Override coder model
--skip-tier1           Skip Tier 1 reviewers
--skip-tier2           Skip Tier 2 reviewers
--verbose              Verbose output
```

## Dependencies

- Python 3.6+
- PyYAML (optional — falls back to defaults without it)
- OpenClaw models.json with configured providers
- No other dependencies (uses stdlib urllib)
```
