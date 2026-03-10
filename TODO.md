# Neuron-Loop Roadmap

## Resilient Handoff / Resume from Checkpoint
- When loop breaks (coder crash, reviewer auth failure, timeout), save checkpoint state
- Checkpoint: current files, iteration number, findings history, addressed fingerprints
- Allow resuming with `--resume <run-dir>` — picks up from last good state
- Automatic provider fallback: if a provider 401s/429s, swap in backup from config
- Example: Anthropic dies → swap Sonnet for GPT-5.4 as reviewer, continue same run
- Florian's idea (2026-03-10)

## Provider Failover in Config
```yaml
failover:
  anthropic: openai    # If Anthropic fails, use OpenAI
  xai: openrouter      # If xAI fails, use OpenRouter
```
