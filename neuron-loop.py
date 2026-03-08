#!/usr/bin/env python3
"""
Neuron-Loop: Coding ↔ Review ↔ Test Loop Orchestrator

A multi-model code review and fix pipeline that:
1. Runs tests (if configured)
2. Sends code to multiple reviewer models in parallel
3. Triages findings using gate rules
4. Sends actionable findings to a coder model for fixes
5. Loops until convergence (no more findings) or max iterations

Usage:
    python3 neuron-loop.py --task TASK.md --files script.lua [script2.py ...]
    python3 neuron-loop.py --task TASK.md --files script.lua --config config.yaml
    python3 neuron-loop.py --task TASK.md --files script.lua --test "bash run_tests.sh"
"""

import argparse
import json
import os
import sys
import time
import hashlib
import threading
import subprocess
import re
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Constants ──────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"
OPENCLAW_MODELS = Path.home() / ".openclaw/agents/main/agent/models.json"

# ─── Provider API Clients ──────────────────────────────────

import urllib.request
import urllib.error
import ssl


def load_openclaw_providers():
    """Load provider configs from OpenClaw's models.json."""
    if not OPENCLAW_MODELS.exists():
        print("[ERROR] Cannot find OpenClaw models.json at", OPENCLAW_MODELS)
        sys.exit(1)
    with open(OPENCLAW_MODELS) as f:
        data = json.load(f)
    return data.get("providers", {})


def api_call_openai_compat(base_url, api_key, model, messages, max_tokens=8192, timeout=300):
    """Call an OpenAI-compatible API (OpenAI, xAI, Ollama Cloud, OpenRouter)."""
    url = f"{base_url.rstrip('/')}/chat/completions"
    # OpenAI's newer models require max_completion_tokens instead of max_tokens
    is_openai = "api.openai.com" in base_url
    token_key = "max_completion_tokens" if is_openai else "max_tokens"
    body = json.dumps({
        "model": model,
        "messages": messages,
        token_key: max_tokens,
        "temperature": 0.2,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")[:500]
        print(f"[ERROR] API {url} returned {e.code}: {error_body}")
        return None
    except Exception as e:
        print(f"[ERROR] API call to {url} failed: {e}")
        return None


def api_call_anthropic(api_key, model, messages, max_tokens=8192, timeout=300):
    """Call Anthropic's native API."""
    url = "https://api.anthropic.com/v1/messages"

    # Convert from OpenAI format to Anthropic format
    system_msg = ""
    anthropic_messages = []
    for m in messages:
        if m["role"] == "system":
            system_msg = m["content"]
        else:
            anthropic_messages.append({"role": m["role"], "content": m["content"]})

    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "messages": anthropic_messages,
        "system": system_msg,
        "temperature": 0.2,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            # Anthropic returns content as array of blocks
            content_blocks = data.get("content", [])
            text_parts = [b["text"] for b in content_blocks if b.get("type") == "text"]
            return "\n".join(text_parts)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")[:500]
        print(f"[ERROR] Anthropic API returned {e.code}: {error_body}")
        return None
    except Exception as e:
        print(f"[ERROR] Anthropic API call failed: {e}")
        return None


def api_call_ollama(base_url, model, messages, max_tokens=8192, timeout=600):
    """Call Ollama's native /api/chat endpoint."""
    url = f"{base_url.rstrip('/')}/api/chat"
    body = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {
            "num_predict": max_tokens,
            "temperature": 0.2,
        },
    }).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("message", {}).get("content", "")
    except Exception as e:
        print(f"[ERROR] Ollama API call failed: {e}")
        return None


class ModelClient:
    """Unified interface for calling any configured model."""

    def __init__(self, providers):
        self.providers = providers

    def call(self, provider_name, model_id, messages, max_tokens=8192, timeout=300):
        """Call a model through its provider."""
        prov = self.providers.get(provider_name)
        if not prov:
            print(f"[ERROR] Unknown provider: {provider_name}")
            return None

        api_type = prov.get("api", "openai-completions")
        api_key = prov.get("apiKey", "")
        base_url = prov.get("baseUrl", "")

        if api_type == "anthropic":
            return api_call_anthropic(api_key, model_id, messages, max_tokens, timeout)
        elif api_type == "ollama":
            return api_call_ollama(base_url, model_id, messages, max_tokens, timeout)
        else:
            return api_call_openai_compat(base_url, api_key, model_id, messages, max_tokens, timeout)


# ─── Config Loading ─────────────────────────────────────────

def load_config(config_path):
    """Load YAML config (minimal parser — no PyYAML dependency)."""
    # Simple YAML-like parser for our flat config
    # For full YAML, users can install PyYAML
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f)
    except ImportError:
        # Fallback: return defaults
        return default_config()


def default_config():
    """Return default configuration."""
    return {
        "tiers": {
            "coder": {"model": "anthropic/claude-sonnet-4-6", "role": "coder"},
            "tier1": [
                {"provider": "anthropic", "model": "claude-sonnet-4-6", "label": "sonnet"},
                {"provider": "openai", "model": "gpt-5.4", "label": "gpt54"},
            ],
            "tier2": [
                {"provider": "ollama-cloud", "model": "glm-5:cloud", "label": "glm5"},
                {"provider": "openrouter", "model": "auto", "label": "openrouter"},
            ],
        },
        "gate": {
            "auto_fix_threshold": 2,
            "tier1_single_action": "fix",
            "tier2_single_action": "skip_unless_critical",
        },
        "loop": {
            "max_iterations": 10,
            "max_coder_rounds": 20,
            "convergence_threshold": 0,
            "timeout_seconds": 3600,
        },
        "test": {
            "command": "",
            "before_review": True,
            "after_fix": True,
        },
        "output": {
            "dir": "./output",
            "keep_intermediates": True,
            "verbose": True,
        },
    }


# ─── Review Prompt Building ────────────────────────────────

def load_prompt_template(name):
    """Load a prompt template from the prompts directory."""
    path = SCRIPT_DIR / "prompts" / f"{name}.md"
    if path.exists():
        return path.read_text()
    return ""


def build_review_prompt(files_content, context="", standards=""):
    """Build the review prompt with file contents injected."""
    template = load_prompt_template("reviewer")
    if not template:
        template = "Review the following code for bugs, security issues, and correctness.\n\n{file_list}"

    file_list = ""
    for name, content in files_content.items():
        file_list += f"\n### {name}\n```\n{content}\n```\n"

    # Use safe substitution to avoid KeyError on JSON templates with {braces}
    result = template
    result = result.replace("{file_list}", file_list)
    result = result.replace("{context}", context or "General code review.")
    result = result.replace("{standards}", standards or "N/A")
    return result


def build_fix_prompt(files_content, findings_text, context=""):
    """Build the coder fix prompt."""
    template = load_prompt_template("coder")
    if not template:
        template = "Fix the following issues in the code.\n\n{findings}\n\n{code}"

    code = ""
    for name, content in files_content.items():
        code += f"\n### {name}\n```\n{content}\n```\n"

    result = template
    result = result.replace("{code}", code)
    result = result.replace("{findings}", findings_text)
    result = result.replace("{context}", context or "Fix the reported issues.")
    return result


# ─── Finding Extraction ────────────────────────────────────

def extract_findings(response_text):
    """Extract structured findings from a model's review response."""
    if not response_text:
        return []

    # Try to find JSON array in the response
    # Look for [...] pattern
    findings = []

    # Method 1: Find JSON array
    json_match = re.search(r'\[[\s\S]*?\{[\s\S]*?"severity"[\s\S]*?\}[\s\S]*?\]', response_text)
    if json_match:
        try:
            parsed = json.loads(json_match.group())
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass

    # Method 2: Find individual JSON objects
    for m in re.finditer(r'\{[^{}]*"severity"\s*:\s*"[^"]+?"[^{}]*\}', response_text):
        try:
            obj = json.loads(m.group())
            findings.append(obj)
        except json.JSONDecodeError:
            pass

    if findings:
        return findings

    # Method 3: Parse structured text (fallback)
    # Look for numbered findings with severity markers
    text_findings = []
    current = None
    for line in response_text.split("\n"):
        sev_match = re.match(r'.*?\b(CRITICAL|HIGH|MEDIUM|LOW)\b', line, re.IGNORECASE)
        if sev_match and ("finding" in line.lower() or "." in line[:5] or re.match(r'^\s*\d+', line)
                          or re.match(r'^\s*[#*-]', line)):
            if current:
                text_findings.append(current)
            current = {
                "severity": sev_match.group(1).upper(),
                "title": line.strip().lstrip("#*- 0123456789."),
                "description": "",
            }
        elif current:
            current["description"] += line + "\n"

    if current:
        text_findings.append(current)

    return text_findings


def normalize_finding(finding):
    """Normalize a finding to a consistent structure."""
    return {
        "id": finding.get("id", "?"),
        "severity": finding.get("severity", "MEDIUM").upper(),
        "location": finding.get("location", "unknown"),
        "title": finding.get("title", "Untitled finding"),
        "description": finding.get("description", ""),
        "impact": finding.get("impact", ""),
        "suggestion": finding.get("suggestion", ""),
        "false_positive_risk": finding.get("false_positive_risk", "low"),
    }


# ─── Finding Deduplication & Triage ────────────────────────

def fingerprint_finding(f):
    """Create a fuzzy fingerprint for deduplication."""
    # Combine severity + key words from title/description
    text = f"{f.get('severity','')} {f.get('title','')} {f.get('location','')}".lower()
    # Remove common words
    for w in ["the", "a", "an", "is", "in", "for", "of", "to", "and", "or", "not"]:
        text = text.replace(f" {w} ", " ")
    # Normalize whitespace
    text = " ".join(text.split())
    return text


def deduplicate_findings(all_findings_by_model, gate_config):
    """Cross-reference findings across models and apply gate rules.

    Returns list of (finding, models_that_found_it, action) tuples.
    """
    auto_fix = gate_config.get("auto_fix_threshold", 2)
    t1_action = gate_config.get("tier1_single_action", "fix")
    t2_action = gate_config.get("tier2_single_action", "skip_unless_critical")

    # Group findings by fuzzy fingerprint
    fingerprint_map = {}  # fingerprint → [(finding, model_label, tier)]

    for model_label, (findings, tier) in all_findings_by_model.items():
        for f in findings:
            nf = normalize_finding(f)
            fp = fingerprint_finding(nf)
            if fp not in fingerprint_map:
                fingerprint_map[fp] = []
            fingerprint_map[fp].append((nf, model_label, tier))

    # Apply gate rules
    triaged = []
    for fp, entries in fingerprint_map.items():
        n_models = len(entries)
        best_finding = entries[0][0]  # Use first occurrence as canonical
        models = [e[1] for e in entries]
        tiers = set(e[2] for e in entries)

        # Merge: take highest severity across models
        severities = [e[0]["severity"] for e in entries]
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        best_sev = min(severities, key=lambda s: sev_order.get(s, 99))
        best_finding["severity"] = best_sev

        if n_models >= auto_fix:
            action = "fix"
        elif 1 in tiers:  # At least one Tier 1 model found it
            action = t1_action
        else:  # Tier 2 only
            if t2_action == "skip_unless_critical" and best_sev == "CRITICAL":
                action = "fix"
            elif t2_action == "skip_unless_critical":
                action = "skip"
            else:
                action = t2_action

        triaged.append({
            "finding": best_finding,
            "models": models,
            "n_models": n_models,
            "tiers": sorted(tiers),
            "action": action,
        })

    # Sort: fix first, then by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    triaged.sort(key=lambda t: (
        0 if t["action"] == "fix" else 1,
        sev_order.get(t["finding"]["severity"], 99),
    ))

    return triaged


# ─── Test Runner ────────────────────────────────────────────

def run_tests(test_cmd, workdir=None):
    """Run tests. Returns (success, output)."""
    if not test_cmd:
        return True, "(no tests configured)"

    try:
        result = subprocess.run(
            test_cmd, shell=True, capture_output=True, text=True,
            timeout=300, cwd=workdir,
        )
        output = result.stdout + "\n" + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Tests timed out (300s)"
    except Exception as e:
        return False, f"Test execution failed: {e}"


# ─── Code Extraction from Coder Response ───────────────────

def extract_code_from_response(response, filename):
    """Extract code blocks from coder response, keyed by filename."""
    if not response:
        return None

    # Look for fenced code blocks
    # Try to find one that matches the filename
    blocks = re.findall(r'```(?:\w+)?\n(.*?)```', response, re.DOTALL)

    if not blocks:
        return None

    # If only one code block, assume it's the fixed file
    if len(blocks) == 1:
        return blocks[0]

    # If multiple, try to match by filename header
    # Look for "### filename" or "# filename" before code blocks
    pattern = re.compile(
        r'(?:^|\n)#+\s*' + re.escape(filename) + r'.*?\n```(?:\w+)?\n(.*?)```',
        re.DOTALL
    )
    m = pattern.search(response)
    if m:
        return m.group(1)

    # Return the longest code block (likely the full file)
    return max(blocks, key=len)


# ─── Report Generation ─────────────────────────────────────

def generate_report(iteration, triaged, review_results, test_result, output_dir):
    """Generate a markdown report for this iteration."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Neuron-Loop Report — Iteration {iteration}",
        f"Generated: {ts}",
        "",
    ]

    # Test results
    if test_result:
        test_ok, test_out = test_result
        lines.append(f"## Tests: {'✅ PASS' if test_ok else '❌ FAIL'}")
        if not test_ok:
            lines.append(f"```\n{test_out[:2000]}\n```")
        lines.append("")

    # Review summary
    lines.append("## Review Summary")
    lines.append(f"| Model | Findings | Tier |")
    lines.append(f"|-------|----------|------|")
    for label, (findings, tier) in review_results.items():
        lines.append(f"| {label} | {len(findings)} | T{tier} |")
    lines.append("")

    # Triaged findings
    fix_count = sum(1 for t in triaged if t["action"] == "fix")
    skip_count = sum(1 for t in triaged if t["action"] == "skip")
    lines.append(f"## Triaged Findings: {fix_count} to fix, {skip_count} skipped")
    lines.append("")

    for i, t in enumerate(triaged, 1):
        f = t["finding"]
        action_icon = "🔧" if t["action"] == "fix" else "⏭️"
        models_str = ", ".join(t["models"])
        lines.append(f"### {action_icon} {i}. [{f['severity']}] {f['title']}")
        lines.append(f"- **Location:** {f.get('location', '?')}")
        lines.append(f"- **Models:** {models_str} ({t['n_models']} models)")
        lines.append(f"- **Action:** {t['action']}")
        if f.get("description"):
            lines.append(f"- **Details:** {f['description'][:500]}")
        if f.get("suggestion"):
            lines.append(f"- **Fix:** {f['suggestion'][:500]}")
        lines.append("")

    report = "\n".join(lines)

    # Write to file
    report_path = Path(output_dir) / f"iteration-{iteration:02d}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    return report_path, report


# ─── Main Orchestrator ─────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Neuron-Loop: Coding ↔ Review ↔ Test Orchestrator"
    )
    parser.add_argument("--task", required=True, help="Task/context file (markdown)")
    parser.add_argument("--files", nargs="+", required=True, help="Files to review/fix")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Config file")
    parser.add_argument("--test", default="", help="Test command (overrides config)")
    parser.add_argument("--standards", default="", help="Standards file for comparison")
    parser.add_argument("--output", default="", help="Output directory (overrides config)")
    parser.add_argument("--max-iter", type=int, default=0, help="Max iterations (overrides config)")
    parser.add_argument("--review-only", action="store_true", help="Review only, no fixes")
    parser.add_argument("--coder-model", default="", help="Override coder model (provider/model)")
    parser.add_argument("--skip-tier2", action="store_true", help="Skip Tier 2 reviewers")
    parser.add_argument("--skip-tier1", action="store_true", help="Skip Tier 1 reviewers")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    # Load config
    config = load_config(args.config) if Path(args.config).exists() else default_config()

    # Override from args
    if args.test:
        config["test"]["command"] = args.test
    if args.output:
        config["output"]["dir"] = args.output
    if args.max_iter:
        config["loop"]["max_iterations"] = args.max_iter
    if args.verbose:
        config["output"]["verbose"] = True

    output_dir = config["output"]["dir"]
    verbose = config["output"]["verbose"]
    max_iter = config["loop"]["max_iterations"]
    convergence = config["loop"]["convergence_threshold"]
    test_cmd = config["test"]["command"]

    # Load providers
    providers = load_openclaw_providers()
    client = ModelClient(providers)

    # Load task context
    task_path = Path(args.task)
    if not task_path.exists():
        print(f"[ERROR] Task file not found: {task_path}")
        sys.exit(1)
    task_context = task_path.read_text()

    # Load standards
    standards_text = ""
    if args.standards and Path(args.standards).exists():
        standards_text = Path(args.standards).read_text()

    # Load target files
    files_content = {}
    for fp in args.files:
        p = Path(fp)
        if not p.exists():
            print(f"[ERROR] File not found: {fp}")
            sys.exit(1)
        files_content[p.name] = p.read_text()

    # Build reviewer list
    reviewers = []
    if not args.skip_tier1:
        for r in config["tiers"].get("tier1", []):
            reviewers.append((r["provider"], r["model"], r["label"], 1))
    if not args.skip_tier2:
        for r in config["tiers"].get("tier2", []):
            reviewers.append((r["provider"], r["model"], r["label"], 2))

    if not reviewers:
        print("[ERROR] No reviewers configured")
        sys.exit(1)

    # Determine coder model
    coder_spec = args.coder_model or config["tiers"]["coder"]["model"]
    if "/" in coder_spec:
        coder_provider, coder_model = coder_spec.split("/", 1)
    else:
        coder_provider = "anthropic"
        coder_model = coder_spec

    start_time = time.time()

    print("=" * 60)
    print("  NEURON-LOOP — Code Review & Fix Orchestrator")
    print("=" * 60)
    print(f"  Task:      {task_path.name}")
    print(f"  Files:     {', '.join(files_content.keys())}")
    print(f"  Reviewers: {', '.join(r[2] for r in reviewers)}")
    print(f"  Coder:     {coder_provider}/{coder_model}")
    print(f"  Max iter:  {max_iter}")
    print(f"  Tests:     {'yes' if test_cmd else 'none'}")
    print("=" * 60)
    print()

    for iteration in range(1, max_iter + 1):
        elapsed = time.time() - start_time
        if elapsed > config["loop"]["timeout_seconds"]:
            print(f"\n[TIMEOUT] {config['loop']['timeout_seconds']}s exceeded. Stopping.")
            break

        print(f"╔══════════════════════════════════════════════════╗")
        print(f"║  Iteration {iteration}/{max_iter}                              ║")
        print(f"╚══════════════════════════════════════════════════╝")

        # ── Step 1: Tests ──
        test_result = None
        if test_cmd and config["test"]["before_review"]:
            print("\n📋 Running tests...")
            test_ok, test_out = run_tests(test_cmd)
            test_result = (test_ok, test_out)
            if test_ok:
                print("   ✅ Tests passed")
            else:
                print(f"   ❌ Tests failed:\n{test_out[:500]}")
                if not args.review_only:
                    print("   Sending test failures to coder...")
                    # TODO: send test failures to coder for fixing
                    # For now, continue to review phase

        # ── Step 2: Review ──
        print(f"\n🔍 Sending to {len(reviewers)} reviewers...")

        review_prompt = build_review_prompt(files_content, task_context, standards_text)
        messages = [
            {"role": "system", "content": "You are a senior code reviewer. Return findings as JSON."},
            {"role": "user", "content": review_prompt},
        ]

        review_results = {}  # label → (findings, tier)

        def run_review(provider, model, label, tier):
            t0 = time.time()
            if verbose:
                print(f"   ⏳ {label} ({provider}/{model})...")
            response = client.call(provider, model, messages, max_tokens=8192, timeout=300)
            dt = time.time() - t0
            if response:
                findings = extract_findings(response)
                if verbose:
                    print(f"   ✅ {label}: {len(findings)} findings ({dt:.1f}s)")

                # Save raw response
                raw_path = Path(output_dir) / f"iter-{iteration:02d}-{label}-raw.md"
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                raw_path.write_text(response)

                return label, findings, tier
            else:
                print(f"   ❌ {label}: failed ({dt:.1f}s)")
                return label, [], tier

        # Run reviewers in parallel
        with ThreadPoolExecutor(max_workers=len(reviewers)) as pool:
            futures = {
                pool.submit(run_review, prov, model, label, tier): label
                for prov, model, label, tier in reviewers
            }
            for future in as_completed(futures):
                label, findings, tier = future.result()
                review_results[label] = (findings, tier)

        # ── Step 3: Triage ──
        print("\n⚖️  Triaging findings...")
        triaged = deduplicate_findings(review_results, config["gate"])

        fix_items = [t for t in triaged if t["action"] == "fix"]
        skip_items = [t for t in triaged if t["action"] == "skip"]

        print(f"   🔧 Fix: {len(fix_items)}")
        print(f"   ⏭️  Skip: {len(skip_items)}")

        for t in fix_items:
            f = t["finding"]
            models_str = ", ".join(t["models"])
            print(f"   [{f['severity']}] {f['title']} — found by: {models_str}")

        # ── Step 4: Report ──
        report_path, report = generate_report(
            iteration, triaged, review_results, test_result, output_dir
        )
        print(f"\n📄 Report: {report_path}")

        # ── Step 5: Check convergence ──
        if len(fix_items) <= convergence:
            print(f"\n🎉 Converged! {len(fix_items)} findings ≤ threshold {convergence}")
            break

        if args.review_only:
            print("\n📝 Review-only mode. Stopping.")
            break

        # ── Step 6: Fix ──
        print(f"\n🔧 Sending {len(fix_items)} findings to coder ({coder_provider}/{coder_model})...")

        findings_text = ""
        for i, t in enumerate(fix_items, 1):
            f = t["finding"]
            findings_text += f"\n### {i}. [{f['severity']}] {f['title']}\n"
            findings_text += f"Location: {f.get('location', '?')}\n"
            findings_text += f"Description: {f.get('description', '')}\n"
            if f.get("suggestion"):
                findings_text += f"Suggested fix: {f['suggestion']}\n"

        fix_prompt = build_fix_prompt(files_content, findings_text, task_context)
        fix_messages = [
            {"role": "system", "content": "You are a senior engineer. Fix the reported issues. Return the complete fixed file(s) in code blocks."},
            {"role": "user", "content": fix_prompt},
        ]

        fix_response = client.call(coder_provider, coder_model, fix_messages, max_tokens=16384, timeout=600)

        if fix_response:
            # Save raw coder response
            fix_path = Path(output_dir) / f"iter-{iteration:02d}-coder-response.md"
            fix_path.write_text(fix_response)

            # Extract fixed code and update files
            files_updated = False
            for filename in list(files_content.keys()):
                new_code = extract_code_from_response(fix_response, filename)
                if new_code and len(new_code.strip()) > 100:
                    # Sanity check: new code shouldn't be drastically shorter
                    old_len = len(files_content[filename])
                    new_len = len(new_code)
                    if new_len >= old_len * 0.5:  # Allow up to 50% shrinkage
                        files_content[filename] = new_code
                        files_updated = True
                        print(f"   ✅ Updated {filename} ({old_len} → {new_len} chars)")

                        # Write updated file back to disk
                        for fp in args.files:
                            if Path(fp).name == filename:
                                Path(fp).write_text(new_code)
                                break
                    else:
                        print(f"   ⚠️  {filename}: new code too short ({new_len} vs {old_len}), skipping")
                else:
                    print(f"   ⚠️  Could not extract fixed code for {filename}")

            if not files_updated:
                print("   ❌ No files updated. Breaking loop.")
                break

            # ── Step 7: Post-fix tests ──
            if test_cmd and config["test"]["after_fix"]:
                print("\n📋 Running post-fix tests...")
                test_ok, test_out = run_tests(test_cmd)
                if test_ok:
                    print("   ✅ Tests still pass")
                else:
                    print(f"   ❌ Tests broken after fix:\n{test_out[:500]}")
                    print("   Reverting would go here (not yet implemented)")
                    # TODO: revert and retry
        else:
            print("   ❌ Coder failed to respond. Breaking loop.")
            break

        print()

    # ── Final Summary ──
    elapsed = time.time() - start_time
    print()
    print("=" * 60)
    print(f"  NEURON-LOOP COMPLETE")
    print(f"  Iterations: {iteration}")
    print(f"  Elapsed:    {elapsed:.0f}s")
    print(f"  Reports:    {output_dir}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
