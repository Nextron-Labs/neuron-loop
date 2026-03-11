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
import subprocess
import re
import logging
import copy
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Constants ──────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent
DEFAULT_CONFIG = SCRIPT_DIR / "config.yaml"
OPENCLAW_MODELS = Path.home() / ".openclaw/agents/main/agent/models.json"
VERSION = "0.5.0"

# ─── Logging Setup ──────────────────────────────────────────

import urllib.request
import urllib.error
import ssl


class StructuredLogger:
    """Structured logging with both human-readable console and JSON file output."""

    def __init__(self, run_dir, verbose=True):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose

        # JSON event log — every structured event
        self.events_path = self.run_dir / "events.jsonl"
        self.events_file = open(self.events_path, "a")

        # Human-readable log
        self.log_path = self.run_dir / "neuron-loop.log"
        self.log_file = open(self.log_path, "a")

        self._event_id = 0

    def _ts(self):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write_event(self, event_type, data):
        self._event_id += 1
        event = {
            "id": self._event_id,
            "ts": self._ts(),
            "type": event_type,
            **data,
        }
        self.events_file.write(json.dumps(event, default=str) + "\n")
        self.events_file.flush()
        return event

    def _write_log(self, level, msg):
        ts = self._ts()
        line = f"[{ts}] [{level}] {msg}"
        self.log_file.write(line + "\n")
        self.log_file.flush()
        if self.verbose:
            print(line)

    def info(self, msg, **data):
        self._write_log("INFO", msg)
        if data:
            self._write_event("info", {"message": msg, **data})

    def warn(self, msg, **data):
        self._write_log("WARN", msg)
        self._write_event("warning", {"message": msg, **data})

    def error(self, msg, **data):
        self._write_log("ERROR", msg)
        self._write_event("error", {"message": msg, **data})

    def event(self, event_type, **data):
        self._write_event(event_type, data)

    def close(self):
        self.events_file.close()
        self.log_file.close()


# ─── Run Directory Structure ────────────────────────────────

class RunStorage:
    """Manages structured storage for a single Neuron-Loop run.

    Directory layout:
        runs/
          YYYY-MM-DD_HHMMSS_{task_name}/
            config.json              — frozen config snapshot (no secrets)
            task.md                  — copy of task prompt
            events.jsonl             — structured event log
            neuron-loop.log          — human-readable log
            summary.json             — final summary
            files/
              original/              — original file snapshots
              iter-01/               — files after iteration 1 fixes
              iter-02/               — ...
            reviews/
              iter-01/
                sonnet-raw.md        — raw response
                sonnet-findings.json — extracted findings
                gpt54-raw.md
                gpt54-findings.json
              iter-02/
                ...
            triage/
              iter-01.json           — triaged/deduplicated findings
            fixes/
              iter-01-request.md     — prompt sent to coder
              iter-01-response.md    — raw coder response
            tests/
              iter-01-pre.txt        — pre-review test output
              iter-01-post.txt       — post-fix test output
    """

    def __init__(self, base_dir, task_name):
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        safe_name = re.sub(r'[^\w-]', '_', task_name)[:40]
        self.run_dir = Path(base_dir) / f"{ts}_{safe_name}"
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Sub-directories
        for subdir in ["files/original", "reviews", "triage", "fixes", "tests"]:
            (self.run_dir / subdir).mkdir(parents=True, exist_ok=True)

    def save_config(self, config):
        """Save config snapshot (strip any accidentally included secrets)."""
        safe = copy.deepcopy(config)
        # Remove anything that looks like a key
        for key in list(safe.keys()):
            if "key" in key.lower() or "secret" in key.lower() or "token" in key.lower():
                safe[key] = "***REDACTED***"
        (self.run_dir / "config.json").write_text(json.dumps(safe, indent=2, default=str))

    def save_task(self, task_text):
        (self.run_dir / "task.md").write_text(task_text)

    def save_original_file(self, filename, content):
        (self.run_dir / "files" / "original" / filename).write_text(content)

    def save_iteration_file(self, iteration, filename, content):
        iter_dir = self.run_dir / "files" / f"iter-{iteration:02d}"
        iter_dir.mkdir(parents=True, exist_ok=True)
        (iter_dir / filename).write_text(content)

    def save_review(self, iteration, label, raw_response, findings):
        review_dir = self.run_dir / "reviews" / f"iter-{iteration:02d}"
        review_dir.mkdir(parents=True, exist_ok=True)
        (review_dir / f"{label}-raw.md").write_text(raw_response or "(no response)")
        (review_dir / f"{label}-findings.json").write_text(
            json.dumps(findings, indent=2, default=str)
        )

    def save_triage(self, iteration, triaged):
        (self.run_dir / "triage" / f"iter-{iteration:02d}.json").write_text(
            json.dumps(triaged, indent=2, default=str)
        )

    def save_fix_request(self, iteration, prompt):
        (self.run_dir / "fixes" / f"iter-{iteration:02d}-request.md").write_text(prompt)

    def save_fix_response(self, iteration, response):
        (self.run_dir / "fixes" / f"iter-{iteration:02d}-response.md").write_text(
            response or "(no response)"
        )

    def save_test_output(self, iteration, phase, success, output):
        (self.run_dir / "tests" / f"iter-{iteration:02d}-{phase}.txt").write_text(
            f"# Result: {'PASS' if success else 'FAIL'}\n\n{output}"
        )

    def save_summary(self, summary):
        (self.run_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))

    def save_checkpoint(self, iteration, files_content, model_stats, addressed_fingerprints,
                        last_good_files):
        """Save checkpoint state for resume capability."""
        checkpoint = {
            "version": VERSION,
            "iteration": iteration,
            "files_content": files_content,
            "last_good_files": last_good_files,
            "model_stats": {k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
                           for k, v in model_stats.items()},
            "addressed_fingerprints": list(addressed_fingerprints),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        (self.run_dir / "checkpoint.json").write_text(
            json.dumps(checkpoint, indent=2, default=str))

    @staticmethod
    def load_checkpoint(run_dir):
        """Load checkpoint from a previous run directory."""
        cp_path = Path(run_dir) / "checkpoint.json"
        if not cp_path.exists():
            return None
        return json.loads(cp_path.read_text())


# ─── Provider API Clients ──────────────────────────────────

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
    is_openai = "api.openai.com" in base_url
    is_ollama_cloud = "ollama.com" in base_url
    token_key = "max_completion_tokens" if is_openai else "max_tokens"
    payload = {
        "model": model,
        "messages": messages,
        token_key: max_tokens,
        "temperature": 0.2,
    }
    # Disable thinking for Ollama Cloud qwen models (content comes back empty otherwise)
    if is_ollama_cloud:
        payload["reasoning_effort"] = "none"
    body = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": f"neuron-loop/{VERSION}",
    }

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            usage = data.get("usage", {})
            content = data["choices"][0]["message"]["content"]
            return content, usage
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"HTTP {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}")


def api_call_anthropic(api_key, model, messages, max_tokens=8192, timeout=300):
    """Call Anthropic's native API."""
    url = "https://api.anthropic.com/v1/messages"

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
            content_blocks = data.get("content", [])
            text_parts = [b["text"] for b in content_blocks if b.get("type") == "text"]
            usage = data.get("usage", {})
            return "\n".join(text_parts), usage
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"HTTP {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}")


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
            content = data.get("message", {}).get("content", "")
            usage = {
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            }
            return content, usage
    except Exception as e:
        raise RuntimeError(f"Ollama call failed: {e}")


class ModelClient:
    """Unified interface for calling any configured model."""

    def __init__(self, providers, logger):
        self.providers = providers
        self.logger = logger

    def call(self, provider_name, model_id, messages, max_tokens=8192, timeout=300):
        """Call a model. Returns (content, usage_dict). Raises RuntimeError on failure."""
        prov = self.providers.get(provider_name)
        if not prov:
            raise RuntimeError(f"Unknown provider: {provider_name}")

        api_type = prov.get("api", "openai-completions")
        api_key = prov.get("apiKey", "")
        base_url = prov.get("baseUrl", "")

        t0 = time.time()
        try:
            if api_type == "anthropic":
                content, usage = api_call_anthropic(api_key, model_id, messages, max_tokens, timeout)
            elif api_type == "ollama":
                content, usage = api_call_ollama(base_url, model_id, messages, max_tokens, timeout)
            else:
                content, usage = api_call_openai_compat(base_url, api_key, model_id, messages, max_tokens, timeout)

            elapsed = time.time() - t0
            self.logger.event("api_call", provider=provider_name, model=model_id,
                              elapsed_s=round(elapsed, 1), usage=usage, success=True)
            return content, usage

        except RuntimeError as e:
            elapsed = time.time() - t0
            self.logger.event("api_call", provider=provider_name, model=model_id,
                              elapsed_s=round(elapsed, 1), success=False, error=str(e))
            raise


# ─── Config Loading ─────────────────────────────────────────

def load_config(config_path):
    """Load YAML config."""
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f)
    except ImportError:
        return default_config()


def default_config():
    """Return default configuration."""
    return {
        "tiers": {
            "coder": {"model": "anthropic/claude-opus-4-6", "role": "coder"},
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
            "max_iterations": 15,
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
            "dir": "./runs",
            "keep_intermediates": True,
            "verbose": True,
        },
    }


# ─── Prompt Building ───────────────────────────────────────

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
        template = "Review the following code for bugs and security issues.\n\n{file_list}"

    file_list = ""
    for name, content in files_content.items():
        file_list += f"\n### {name}\n```\n{content}\n```\n"

    result = template
    result = result.replace("{file_list}", file_list)
    result = result.replace("{context}", context or "General code review.")
    result = result.replace("{standards}", standards or "N/A")
    return result


def build_fix_prompt(files_content, findings_text, context=""):
    """Build the coder fix prompt."""
    template = load_prompt_template("coder")
    if not template:
        template = "Fix the following issues.\n\n{findings}\n\n{code}"

    code = ""
    for name, content in files_content.items():
        code += f"\n### {name}\n```\n{content}\n```\n"

    result = template
    result = result.replace("{code}", code)
    result = result.replace("{findings}", findings_text)
    result = result.replace("{context}", context or "Fix the reported issues.")
    return result


def build_improve_prompt(files_content, context=""):
    """Build the improve prompt — coder reviews and improves the script itself."""
    template = load_prompt_template("improver")
    if not template:
        template = """Review and improve the following script. You are both reviewer and coder.

## Task Context
{context}

## Instructions
1. Carefully review the script for bugs, security issues, edge cases, and correctness
2. Produce an improved version using SEARCH/REPLACE blocks
3. Focus on: logic errors, security vulnerabilities, error handling, edge cases, platform compatibility
4. Do NOT rewrite the entire script — make targeted improvements
5. Do NOT change the script's interface (CLI flags, exit codes) unless fixing a bug
6. Preserve the script's style and structure where possible

## Current Script
{code}

Return ONLY SEARCH/REPLACE blocks using <<<SEARCH, >>>REPLACE, <<<END delimiters.
Label each fix with a brief comment (e.g. ### Fix 1: description)."""

    code = ""
    for name, content in files_content.items():
        code += f"\n### {name}\n```\n{content}\n```\n"

    result = template
    result = result.replace("{code}", code)
    result = result.replace("{context}", context or "Review and improve this script.")
    return result


# ─── Finding Extraction ────────────────────────────────────

def extract_findings(response_text):
    """Extract structured findings from a model's review response."""
    if not response_text:
        return []

    findings = []

    # Method 1: Find JSON array with severity fields
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
    text_findings = []
    current = None
    for line in response_text.split("\n"):
        sev_match = re.match(r'.*?\b(CRITICAL|HIGH|MEDIUM|LOW)\b', line, re.IGNORECASE)
        if sev_match and (re.match(r'^\s*[\d#*-]', line) or "finding" in line.lower()):
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
    text = f"{f.get('severity','')} {f.get('title','')} {f.get('location','')}".lower()
    stopwords = {"the", "a", "an", "is", "in", "for", "of", "to", "and", "or", "not",
                 "no", "does", "are", "has", "have", "with", "on", "by", "it"}
    words = [w for w in text.split() if w not in stopwords and len(w) > 2]
    return " ".join(sorted(set(words)))


def similarity(fp1, fp2):
    """Jaccard similarity between two fingerprints."""
    w1 = set(fp1.split())
    w2 = set(fp2.split())
    if not w1 or not w2:
        return 0.0
    return len(w1 & w2) / len(w1 | w2)


def deduplicate_findings(all_findings_by_model, gate_config, addressed_fingerprints=None):
    """Cross-reference findings across models and apply gate rules.

    addressed_fingerprints: set of fingerprints from prior iterations that were already
    sent to the coder. Findings matching these are downgraded to 'skip' unless they
    were explicitly marked as not fixed.
    """
    auto_fix = gate_config.get("auto_fix_threshold", 2)
    t1_action = gate_config.get("tier1_single_action", "fix")
    t2_action = gate_config.get("tier2_single_action", "skip_unless_critical")
    if addressed_fingerprints is None:
        addressed_fingerprints = set()

    SIMILARITY_THRESHOLD = 0.35

    # Collect all findings with metadata
    all_entries = []
    for model_label, (findings, tier) in all_findings_by_model.items():
        for f in findings:
            nf = normalize_finding(f)
            fp = fingerprint_finding(nf)
            all_entries.append((nf, model_label, tier, fp))

    # Cluster by similarity
    clusters = []  # Each cluster: list of (finding, model, tier, fingerprint)
    used = set()

    for i, (f1, m1, t1, fp1) in enumerate(all_entries):
        if i in used:
            continue
        cluster = [(f1, m1, t1, fp1)]
        used.add(i)
        for j, (f2, m2, t2, fp2) in enumerate(all_entries):
            if j in used:
                continue
            if similarity(fp1, fp2) >= SIMILARITY_THRESHOLD:
                cluster.append((f2, m2, t2, fp2))
                used.add(j)
        clusters.append(cluster)

    # Apply gate rules per cluster
    triaged = []
    for cluster in clusters:
        models = list(set(e[1] for e in cluster))
        tiers = set(e[2] for e in cluster)
        n_models = len(models)

        # Use the highest-severity finding as canonical
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        best = min(cluster, key=lambda e: sev_order.get(e[0]["severity"], 99))
        finding = best[0]

        if n_models >= auto_fix:
            action = "fix"
        elif 1 in tiers:
            action = t1_action
        else:
            if t2_action == "skip_unless_critical" and finding["severity"] == "CRITICAL":
                action = "fix"
            elif t2_action == "skip_unless_critical":
                action = "skip"
            else:
                action = t2_action

        # Check if this finding was already addressed in a prior iteration
        cluster_fp = fingerprint_finding(finding)
        already_addressed = any(
            similarity(cluster_fp, afp) >= SIMILARITY_THRESHOLD
            for afp in addressed_fingerprints
        )
        if already_addressed and action == "fix":
            action = "skip"
            finding["_skip_reason"] = "already addressed in prior iteration"

        triaged.append({
            "finding": finding,
            "models": models,
            "n_models": n_models,
            "tiers": sorted(tiers),
            "action": action,
            "cluster_size": len(cluster),
            "fingerprint": cluster_fp,
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


# ─── Code Extraction & Diff Application ────────────────────

def extract_code_from_response(response, filename):
    """Extract code blocks from coder response (legacy full-file mode)."""
    if not response:
        return None

    blocks = re.findall(r'```(?:\w+)?\n(.*?)```', response, re.DOTALL)
    if not blocks:
        return None

    if len(blocks) == 1:
        return blocks[0]

    pattern = re.compile(
        r'(?:^|\n)#+\s*' + re.escape(filename) + r'.*?\n```(?:\w+)?\n(.*?)```',
        re.DOTALL
    )
    m = pattern.search(response)
    if m:
        return m.group(1)

    return max(blocks, key=len)


def parse_search_replace_blocks(response):
    """Parse SEARCH/REPLACE blocks from coder response.

    Returns list of (search_text, replace_text, finding_info) tuples.
    """
    if not response:
        return []

    blocks = []

    # Pattern: <<<SEARCH ... >>>REPLACE ... <<<END (also accept >>>END)
    pattern = re.compile(
        r'<<<SEARCH\s*\n(.*?)>>>REPLACE\s*\n(.*?)(?:<<<END|>>>END)',
        re.DOTALL
    )

    for m in pattern.finditer(response):
        search = m.group(1)
        replace = m.group(2)

        # Strip trailing newline (the block delimiter adds one)
        if search.endswith('\n'):
            search = search[:-1]
        if replace.endswith('\n'):
            replace = replace[:-1]

        # Find the associated finding header (look backwards for ### Finding N)
        preceding = response[:m.start()]
        finding_match = re.search(r'###\s*Finding\s*(\d+)\s*:\s*(\w+)', preceding[::-1][:500][::-1])
        finding_info = finding_match.group(0) if finding_match else "unknown"

        blocks.append((search, replace, finding_info))

    return blocks


def sanitize_replacement(text):
    """Strip stray SEARCH/REPLACE format markers from replacement text.
    These can leak when the coder echoes its own format into code."""
    markers = ['<<<SEARCH', '>>>REPLACE', '<<<END', '>>>END']
    for marker in markers:
        text = text.replace(marker, '')
    return text


def apply_search_replace(content, blocks, logger):
    """Apply SEARCH/REPLACE blocks to file content.

    Returns (new_content, applied_count, failed_count).
    """
    applied = 0
    failed = 0

    for search, replace, info in blocks:
        replace = sanitize_replacement(replace)
        if search in content:
            content = content.replace(search, replace, 1)
            applied += 1
            logger.info(f"  Applied: {info}")
        else:
            # Try with whitespace normalization
            search_normalized = re.sub(r'[ \t]+', ' ', search)
            content_normalized = re.sub(r'[ \t]+', ' ', content)
            if search_normalized in content_normalized:
                # Find the actual position and replace
                idx = content_normalized.index(search_normalized)
                # Count newlines to find line range
                line_start = content[:idx].count('\n')
                line_end = line_start + search.count('\n')
                logger.warn(f"  Fuzzy match for {info} (lines {line_start}-{line_end})")

                # Do the replacement on original content using line-based matching
                orig_lines = content.split('\n')
                search_lines = search.split('\n')
                replace_lines = replace.split('\n')

                # Find matching line range
                found = False
                for i in range(len(orig_lines) - len(search_lines) + 1):
                    chunk = orig_lines[i:i + len(search_lines)]
                    if all(a.strip() == b.strip() for a, b in zip(chunk, search_lines)):
                        orig_lines[i:i + len(search_lines)] = replace_lines
                        content = '\n'.join(orig_lines)
                        applied += 1
                        found = True
                        break

                if not found:
                    failed += 1
                    logger.warn(f"  FAILED to apply: {info} (fuzzy match failed)")
            else:
                failed += 1
                logger.warn(f"  FAILED to apply: {info} (search text not found)")

    return content, applied, failed


# ─── Diff Generation ───────────────────────────────────────

def generate_diff(old_content, new_content, filename="file"):
    """Generate a unified diff between old and new content."""
    import difflib
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines,
                                fromfile=f"a/{filename}", tofile=f"b/{filename}")
    return "".join(diff)


def build_verify_prompt(diff_text, findings_text, context=""):
    """Build the verification prompt for diff review."""
    template = load_prompt_template("verifier")
    if not template:
        template = ("Verify these code changes are correct.\n\n"
                    "Diff:\n{diff}\n\nFindings addressed:\n{findings}")

    result = template
    result = result.replace("{diff}", diff_text)
    result = result.replace("{findings}", findings_text)
    result = result.replace("{context}", context or "Verify the fix is correct.")
    return result


def run_diff_verification(client, verifier, diff_text, findings_text, task_context,
                          iteration, storage, logger, model_stats):
    """Run diff verification with the alternate T1 model.

    Returns list of BAD verdicts (empty = all good).
    """
    prov, model, label, tier = verifier
    logger.info(f"🔍 Diff verification by {label} ({prov}/{model})...")

    if label not in model_stats:
        model_stats[label] = {"total_findings": 0, "api_calls": 0, "errors": 0,
                              "provider": prov, "model": model, "tier": tier}
    model_stats[label]["api_calls"] += 1

    verify_prompt = build_verify_prompt(diff_text, findings_text, task_context)
    messages = [
        {"role": "system", "content": "You are a senior engineer verifying code changes. "
         "Return verdicts as JSON array. Empty array [] means all changes are correct."},
        {"role": "user", "content": verify_prompt},
    ]

    t0 = time.time()
    try:
        response, usage = client.call(prov, model, messages, max_tokens=4096, timeout=180)
        dt = time.time() - t0

        logger.event("verify_complete", iteration=iteration, label=label,
                     elapsed_s=round(dt, 1), usage=usage)

        # Save verification response
        verify_dir = storage.run_dir / "verification"
        verify_dir.mkdir(parents=True, exist_ok=True)
        (verify_dir / f"iter-{iteration:02d}-{label}.md").write_text(response or "")

        # Parse verdicts
        bad_verdicts = []
        if response:
            # Try JSON extraction
            json_match = re.search(r'\[[\s\S]*?\]', response)
            if json_match:
                try:
                    verdicts = json.loads(json_match.group())
                    if isinstance(verdicts, list):
                        bad_verdicts = [v for v in verdicts
                                        if isinstance(v, dict) and v.get("verdict") == "BAD"]
                except json.JSONDecodeError:
                    pass

        if bad_verdicts:
            print(f"   ⚠️  {label}: {len(bad_verdicts)} BAD verdict(s) ({dt:.1f}s)")
            for v in bad_verdicts:
                print(f"      → {v.get('issue', 'unknown issue')}")
        else:
            print(f"   ✅ {label}: changes verified ({dt:.1f}s)")

        return bad_verdicts

    except Exception as e:
        dt = time.time() - t0
        # Retry once for transient errors
        retry_codes = ("401", "403", "429", "timeout", "Connection")
        if any(code in str(e) for code in retry_codes):
            logger.warn(f"Verification failed (retrying in 5s): {label} — {e}")
            print(f"   ⚠️  {label}: verification failed — retrying in 5s...")
            time.sleep(5)
            try:
                t1 = time.time()
                response, usage = client.call(prov, model, messages, max_tokens=4096, timeout=180)
                dt2 = time.time() - t1
                model_stats[label]["api_calls"] += 1
                verify_dir = storage.run_dir / "verification"
                verify_dir.mkdir(parents=True, exist_ok=True)
                (verify_dir / f"iter-{iteration:02d}-{label}.md").write_text(response or "")
                bad_verdicts = []
                if response:
                    json_match = re.search(r'\[[\s\S]*?\]', response)
                    if json_match:
                        try:
                            verdicts = json.loads(json_match.group())
                            if isinstance(verdicts, list):
                                bad_verdicts = [v for v in verdicts
                                                if isinstance(v, dict) and v.get("verdict") == "BAD"]
                        except json.JSONDecodeError:
                            pass
                if bad_verdicts:
                    print(f"   ⚠️  {label}: {len(bad_verdicts)} BAD verdict(s) ({dt2:.1f}s, retry)")
                else:
                    print(f"   ✅ {label}: changes verified ({dt2:.1f}s, retry)")
                return bad_verdicts
            except Exception as e2:
                logger.error(f"Verification retry failed: {label} — {e2}")
                print(f"   ❌ {label}: retry failed ({time.time()-t1:.1f}s)")

        model_stats[label]["errors"] += 1
        logger.error(f"Verification failed: {label} — {e}")
        print(f"   ❌ {label}: verification failed ({dt:.1f}s)")
        return []  # Don't block on verification failure


# ─── Report Generation ─────────────────────────────────────

def generate_report(iteration, triaged, review_results, test_result, storage, logger):
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
    lines.append("| Model | Findings | Tier |")
    lines.append("|-------|----------|------|")
    total_findings = 0
    for label, (findings, tier) in review_results.items():
        lines.append(f"| {label} | {len(findings)} | T{tier} |")
        total_findings += len(findings)
    lines.append("")

    # Triaged findings
    fix_items = [t for t in triaged if t["action"] == "fix"]
    skip_items = [t for t in triaged if t["action"] == "skip"]
    lines.append(f"## Triaged: {len(fix_items)} to fix, {len(skip_items)} skipped "
                 f"(from {total_findings} raw findings, {len(triaged)} unique)")
    lines.append("")

    for i, t in enumerate(triaged, 1):
        f = t["finding"]
        action_icon = "🔧" if t["action"] == "fix" else "⏭️"
        models_str = ", ".join(t["models"])
        lines.append(f"### {action_icon} {i}. [{f['severity']}] {f['title']}")
        lines.append(f"- **Location:** {f.get('location', '?')}")
        lines.append(f"- **Models:** {models_str} ({t['n_models']} model{'s' if t['n_models']>1 else ''})")
        lines.append(f"- **Action:** {t['action']}")
        if f.get("description"):
            desc = f['description'].strip()[:500]
            lines.append(f"- **Details:** {desc}")
        if f.get("suggestion"):
            lines.append(f"- **Fix:** {f['suggestion'][:500]}")
        lines.append("")

    report = "\n".join(lines)
    report_path = storage.run_dir / f"report-iter-{iteration:02d}.md"
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
    parser.add_argument("--output", default="", help="Output/runs directory")
    parser.add_argument("--max-iter", type=int, default=0, help="Max iterations")
    parser.add_argument("--review-only", action="store_true", help="Review only, no fixes")
    parser.add_argument("--mode", choices=["review-fix", "improve"], default="review-fix",
                        help="Mode: review-fix (reviewers find, coder fixes) or improve (coder improves, reviewers verify)")
    parser.add_argument("--coder-model", default="", help="Override coder (provider/model)")
    parser.add_argument("--skip-tier2", action="store_true", help="Skip Tier 2 reviewers")
    parser.add_argument("--skip-tier1", action="store_true", help="Skip Tier 1 reviewers")
    parser.add_argument("--resume", default="", help="Resume from a previous run directory")
    parser.add_argument("--verbose", action="store_true", default=True, help="Verbose output")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--version", action="version", version=f"neuron-loop {VERSION}")
    args = parser.parse_args()

    if args.quiet:
        args.verbose = False

    # Load config
    config = load_config(args.config) if Path(args.config).exists() else default_config()

    # Override from args
    if args.test:
        config["test"]["command"] = args.test
    if args.output:
        config["output"]["dir"] = args.output
    if args.max_iter:
        config["loop"]["max_iterations"] = args.max_iter

    output_dir = config["output"]["dir"]
    verbose = args.verbose
    max_iter = config["loop"]["max_iterations"]
    convergence = config["loop"]["convergence_threshold"]
    test_cmd = config["test"]["command"]

    # Load task
    task_path = Path(args.task)
    if not task_path.exists():
        print(f"[ERROR] Task file not found: {task_path}")
        sys.exit(1)
    task_context = task_path.read_text()
    task_name = task_path.stem

    # Initialize storage and logging
    storage = RunStorage(output_dir, task_name)
    logger = StructuredLogger(storage.run_dir, verbose=verbose)

    logger.info(f"Neuron-Loop v{VERSION} starting")
    logger.event("run_start", version=VERSION, task=str(task_path),
                 files=[str(f) for f in args.files])

    # Save config (without secrets)
    storage.save_config(config)
    storage.save_task(task_context)

    # Load providers
    providers = load_openclaw_providers()
    client = ModelClient(providers, logger)

    # Load standards
    standards_text = ""
    if args.standards and Path(args.standards).exists():
        standards_text = Path(args.standards).read_text()

    # Load target files
    files_content = {}
    for fp in args.files:
        p = Path(fp)
        if not p.exists():
            logger.error(f"File not found: {fp}")
            sys.exit(1)
        files_content[p.name] = p.read_text()
        storage.save_original_file(p.name, p.read_text())

    # Build reviewer list
    reviewers = []
    if not args.skip_tier1:
        for r in config["tiers"].get("tier1", []):
            reviewers.append((r["provider"], r["model"], r["label"], 1))
    if not args.skip_tier2:
        for r in config["tiers"].get("tier2", []):
            reviewers.append((r["provider"], r["model"], r["label"], 2))

    if not reviewers:
        logger.error("No reviewers configured")
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
    print(f"  Run:       {storage.run_dir.name}")
    print(f"  Task:      {task_path.name}")
    print(f"  Files:     {', '.join(files_content.keys())}")
    t1_labels = [r[2] for r in reviewers if r[3] == 1]
    t2_labels = [r[2] for r in reviewers if r[3] == 2]
    print(f"  T1 Review: {' ↔ '.join(t1_labels)} (alternating)")
    if t2_labels:
        print(f"  T2 Sweep:  {', '.join(t2_labels)}")
    print(f"  Coder:     {coder_provider}/{coder_model}")
    print(f"  Mode:      {args.mode}")
    print(f"  Max iter:  {max_iter}")
    print(f"  Tests:     {'yes' if test_cmd else 'none'}")
    print(f"  Output:    {storage.run_dir}")
    print("=" * 60)
    print()

    # Track per-model stats across iterations
    model_stats = {}  # label → {"total_findings": N, "api_calls": N, "errors": N}

    # Track findings that were already sent to the coder (cross-iteration dedup)
    addressed_fingerprints = set()

    # Track last known good state for revert-on-test-failure
    last_good_files = {name: content for name, content in files_content.items()}

    # Resume from checkpoint if requested
    start_iteration = 1
    if args.resume:
        checkpoint = RunStorage.load_checkpoint(args.resume)
        if checkpoint:
            start_iteration = checkpoint["iteration"] + 1
            files_content = checkpoint["files_content"]
            last_good_files = checkpoint.get("last_good_files", dict(files_content))
            model_stats = checkpoint.get("model_stats", {})
            addressed_fingerprints = set(checkpoint.get("addressed_fingerprints", []))

            # Write resumed files to disk so the coder works on the right state
            for filename, content in files_content.items():
                for fp in args.files:
                    if Path(fp).name == filename:
                        Path(fp).write_text(content)
                        break

            logger.info(f"Resumed from {args.resume} at iteration {start_iteration}")
            print(f"\n  ♻️  Resuming from iteration {start_iteration} "
                  f"(checkpoint: {args.resume})")
            print()
        else:
            logger.error(f"No checkpoint found in {args.resume}")
            print(f"[ERROR] No checkpoint.json in {args.resume}")
            sys.exit(1)

    iteration = 0
    for iteration in range(start_iteration, max_iter + 1):
        elapsed = time.time() - start_time
        if elapsed > config["loop"]["timeout_seconds"]:
            logger.warn(f"Timeout ({config['loop']['timeout_seconds']}s) exceeded")
            storage.save_checkpoint(iteration - 1, files_content, model_stats,
                                    addressed_fingerprints, last_good_files)
            logger.info(f"Checkpoint saved at iteration {iteration - 1} (timeout)")
            print(f"\n   💾 Checkpoint saved — resume with: --resume {storage.run_dir}")
            break

        logger.event("iteration_start", iteration=iteration)

        print(f"╔══════════════════════════════════════════════════╗")
        print(f"║  Iteration {iteration}/{max_iter}{'':>38}║")
        print(f"╚══════════════════════════════════════════════════╝")

        # ── Step 1: Tests ──
        test_result = None
        if test_cmd and config["test"]["before_review"]:
            logger.info("Running pre-review tests...")
            test_ok, test_out = run_tests(test_cmd)
            test_result = (test_ok, test_out)
            storage.save_test_output(iteration, "pre", test_ok, test_out)
            logger.event("test_run", iteration=iteration, phase="pre", passed=test_ok)
            if test_ok:
                print("   ✅ Tests passed")
            else:
                print(f"   ❌ Tests failed")

        # ── Improve mode: iteration 1 → coder improves, skip review ──
        if args.mode == "improve" and iteration == start_iteration:
            logger.info("Improve mode: sending script to coder for initial review & improvement...")
            print("   🔧 Improve mode — coder reviews and improves the script\n")

            improve_prompt = build_improve_prompt(files_content, task_context)
            improve_messages = [
                {"role": "system", "content": "You are a senior engineer. Review and improve the script. "
                 "Return ONLY SEARCH/REPLACE blocks using <<<SEARCH, >>>REPLACE, <<<END delimiters. "
                 "Do NOT return the entire file."},
                {"role": "user", "content": improve_prompt},
            ]

            try:
                fix_response, fix_usage = client.call(
                    coder_provider, coder_model, improve_messages, max_tokens=16384, timeout=600
                )
                storage.save_fix_request(iteration, improve_prompt)
                storage.save_fix_response(iteration, fix_response)

                logger.event("improve_complete", iteration=iteration,
                             provider=coder_provider, model=coder_model, usage=fix_usage)

                blocks = parse_search_replace_blocks(fix_response)
                if blocks:
                    logger.info(f"Parsed {len(blocks)} SEARCH/REPLACE blocks from improver")
                    files_updated = False
                    for filename in list(files_content.keys()):
                        old_content = files_content[filename]
                        new_content, applied, failed = apply_search_replace(
                            old_content, blocks, logger
                        )
                        if applied > 0:
                            files_content[filename] = new_content
                            files_updated = True
                            storage.save_iteration_file(iteration, filename, new_content)
                            for fp in args.files:
                                if Path(fp).name == filename:
                                    Path(fp).write_text(new_content)
                                    break
                            old_lines = old_content.count('\n') + 1
                            new_lines = new_content.count('\n') + 1
                            logger.info(f"Improved {filename}: {applied} applied, {failed} failed "
                                        f"({old_lines} → {new_lines} lines)")
                            print(f"   ✅ {filename}: {applied} improvements applied "
                                  f"({old_lines} → {new_lines} lines)")
                        else:
                            logger.warn(f"No improvements applied to {filename} ({failed} failed)")
                            print(f"   ❌ No improvements applied to {filename}")

                    if files_updated:
                        last_good_files = {name: content for name, content in files_content.items()}
                        storage.save_checkpoint(iteration, files_content, model_stats,
                                                addressed_fingerprints, last_good_files)
                        print()
                        continue  # → next iteration (reviewers will verify)
                    else:
                        logger.warn("Coder produced no applicable improvements, breaking")
                        print("   ⚠️  No improvements could be applied")
                        break
                else:
                    logger.warn("No SEARCH/REPLACE blocks found in improve response")
                    print("   ⚠️  Coder returned no SEARCH/REPLACE blocks")
                    break

            except Exception as e:
                logger.error(f"Improve step failed: {e}")
                storage.save_fix_response(iteration, f"ERROR: {e}")
                storage.save_checkpoint(iteration, files_content, model_stats,
                                        addressed_fingerprints, last_good_files)
                print(f"\n   💾 Checkpoint saved — resume with: --resume {storage.run_dir}")
                break

        # ── Step 2: Review ──
        # Alternate T1 reviewers: odd iterations use first T1, even use second
        # T2 reviewers always run (they're cheap/free)
        iter_reviewers = []
        t1_list = [r for r in reviewers if r[3] == 1]
        t2_list = [r for r in reviewers if r[3] == 2]

        if t1_list:
            # Alternate: pick one T1 reviewer per iteration
            t1_idx = (iteration - 1) % len(t1_list)
            active_t1 = t1_list[t1_idx]
            iter_reviewers.append(active_t1)
            # The OTHER T1 reviewer will verify the diff later
            verifier_t1 = t1_list[(t1_idx + 1) % len(t1_list)] if len(t1_list) > 1 else None
        else:
            verifier_t1 = None

        iter_reviewers.extend(t2_list)

        logger.info(f"Sending to {len(iter_reviewers)} reviewer(s) "
                     f"(T1: {active_t1[2] if t1_list else 'none'}"
                     f"{', verifier: ' + verifier_t1[2] if verifier_t1 else ''})...")

        review_prompt = build_review_prompt(files_content, task_context, standards_text)
        messages = [
            {"role": "system", "content": "You are a senior code reviewer. Return findings as JSON array."},
            {"role": "user", "content": review_prompt},
        ]

        review_results = {}  # label → (findings, tier)

        def run_review(provider, model, label, tier):
            t0 = time.time()
            logger.info(f"  → {label} ({provider}/{model})")

            # Init stats
            if label not in model_stats:
                model_stats[label] = {"total_findings": 0, "api_calls": 0, "errors": 0,
                                      "provider": provider, "model": model, "tier": tier}
            model_stats[label]["api_calls"] += 1

            try:
                response, usage = client.call(provider, model, messages, max_tokens=8192, timeout=300)
                dt = time.time() - t0
                findings = extract_findings(response)

                model_stats[label]["total_findings"] += len(findings)

                logger.event("review_complete", iteration=iteration, label=label,
                             provider=provider, model=model, tier=tier,
                             findings_count=len(findings), elapsed_s=round(dt, 1),
                             usage=usage)

                # Save raw response and findings
                storage.save_review(iteration, label, response, findings)

                print(f"   ✅ {label}: {len(findings)} findings ({dt:.1f}s)")
                return label, findings, tier

            except Exception as e:
                dt = time.time() - t0
                # Retry once after 5s for transient errors (401, 403, 429, timeouts)
                retry_codes = ("401", "403", "429", "timeout", "Connection")
                if any(code in str(e) for code in retry_codes):
                    logger.warn(f"Review failed (retrying in 5s): {label} — {e}")
                    print(f"   ⚠️  {label}: {e} — retrying in 5s...")
                    time.sleep(5)
                    try:
                        t1 = time.time()
                        response, usage = client.call(prov, model, messages, max_tokens=8192, timeout=300)
                        dt2 = time.time() - t1
                        findings = parse_review_response(response, label)
                        model_stats[label]["api_calls"] += 1
                        model_stats[label]["total_findings"] += len(findings)
                        storage.save_review(iteration, label, response, findings)
                        print(f"   ✅ {label}: {len(findings)} findings ({dt2:.1f}s, retry)")
                        return label, findings, tier
                    except Exception as e2:
                        dt2 = time.time() - t1
                        logger.error(f"Review retry failed: {label} — {e2}")
                        print(f"   ❌ {label}: retry failed — {e2} ({dt2:.1f}s)")

                model_stats[label]["errors"] += 1
                logger.error(f"Review failed: {label} — {e}", label=label, error=str(e))
                storage.save_review(iteration, label, f"ERROR: {e}", [])
                print(f"   ❌ {label}: {e} ({dt:.1f}s)")
                return label, [], tier

        # Run reviewers in parallel
        with ThreadPoolExecutor(max_workers=len(iter_reviewers)) as pool:
            futures = {
                pool.submit(run_review, prov, model, label, tier): label
                for prov, model, label, tier in iter_reviewers
            }
            for future in as_completed(futures):
                label, findings, tier = future.result()
                review_results[label] = (findings, tier)

        # ── Step 3: Triage ──
        logger.info("Triaging findings...")
        triaged = deduplicate_findings(review_results, config["gate"], addressed_fingerprints)
        storage.save_triage(iteration, triaged)

        fix_items = [t for t in triaged if t["action"] == "fix"]
        skip_items = [t for t in triaged if t["action"] == "skip"]

        logger.event("triage_complete", iteration=iteration,
                     total_unique=len(triaged), fix=len(fix_items), skip=len(skip_items))

        reused = sum(1 for t in skip_items if t["finding"].get("_skip_reason"))
        print(f"\n   ⚖️  Triage: {len(fix_items)} fix, {len(skip_items)} skip"
              f"{f' ({reused} already addressed)' if reused else ''}")
        for t in fix_items:
            f = t["finding"]
            models_str = ", ".join(t["models"])
            print(f"   [{f['severity']}] {f['title']} — {models_str}")

        # ── Step 4: Report ──
        report_path, report = generate_report(
            iteration, triaged, review_results, test_result, storage, logger
        )
        logger.info(f"Report: {report_path}")

        # ── Step 5: Convergence check ──
        # Don't converge if any T1 reviewer failed this iteration
        t1_failed = any(
            model_stats[label]["errors"] > 0 and tier == 1
            for label, (findings, tier) in review_results.items()
            if model_stats[label]["errors"] > (model_stats[label].get("_prev_errors", 0))
        )
        if t1_failed:
            # Update prev_errors tracking
            for label in model_stats:
                model_stats[label]["_prev_errors"] = model_stats[label]["errors"]
            if len(fix_items) <= convergence:
                logger.warn(f"Would converge ({len(fix_items)} findings) but T1 reviewer failed — "
                             "not trustworthy, continuing")
                print(f"\n⚠️  T1 reviewer failed this iteration — skipping convergence check")
                continue

        # Update prev_errors tracking
        for label in model_stats:
            model_stats[label]["_prev_errors"] = model_stats[label]["errors"]

        # Severity-aware convergence: only MEDIUM+ findings count
        min_severity = config.get("loop", {}).get("min_fix_severity", "LOW").upper()
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        min_rank = sev_rank.get(min_severity, 3)
        significant_fixes = [t for t in fix_items
                             if sev_rank.get(t["finding"]["severity"], 3) <= min_rank]

        if len(significant_fixes) <= convergence:
            if fix_items and not significant_fixes:
                logger.info(f"Converged: {len(fix_items)} remaining findings are all below {min_severity} — stopping")
                print(f"\n🎉 Converged! Only minor ({min_severity.lower()}-excluded) findings remain.")
            else:
                logger.info(f"Converged: {len(significant_fixes)} significant findings ≤ threshold {convergence}")
                print(f"\n🎉 Converged!")
            break

        if args.review_only:
            logger.info("Review-only mode, stopping")
            print("\n📝 Review-only mode. Stopping.")
            break

        # ── Step 6: Fix ──
        logger.info(f"Sending {len(fix_items)} findings to coder...")

        findings_text = ""
        for i, t in enumerate(fix_items, 1):
            f = t["finding"]
            findings_text += f"\n### Finding {i}. [{f['severity']}] {f['title']}\n"
            findings_text += f"Location: {f.get('location', '?')}\n"
            findings_text += f"Description: {f.get('description', '')}\n"
            if f.get("suggestion"):
                findings_text += f"Suggested fix: {f['suggestion']}\n"
            # Track this finding as addressed for cross-iteration dedup
            if t.get("fingerprint"):
                addressed_fingerprints.add(t["fingerprint"])

        fix_prompt = build_fix_prompt(files_content, findings_text, task_context)
        storage.save_fix_request(iteration, fix_prompt)

        fix_messages = [
            {"role": "system", "content": "You are a senior engineer. Fix the reported issues using "
             "SEARCH/REPLACE blocks. Do NOT return the entire file — only the changed sections. "
             "Use <<<SEARCH, >>>REPLACE, <<<END delimiters."},
            {"role": "user", "content": fix_prompt},
        ]

        try:
            fix_response, fix_usage = client.call(
                coder_provider, coder_model, fix_messages, max_tokens=8192, timeout=600
            )
            storage.save_fix_response(iteration, fix_response)

            logger.event("coder_complete", iteration=iteration,
                         provider=coder_provider, model=coder_model, usage=fix_usage)

            # Parse SEARCH/REPLACE blocks
            blocks = parse_search_replace_blocks(fix_response)

            if blocks:
                logger.info(f"Parsed {len(blocks)} SEARCH/REPLACE blocks")

                files_updated = False
                for filename in list(files_content.keys()):
                    old_content = files_content[filename]
                    new_content, applied, failed = apply_search_replace(
                        old_content, blocks, logger
                    )

                    if applied > 0:
                        files_content[filename] = new_content
                        files_updated = True

                        # Save to storage and write back to disk
                        storage.save_iteration_file(iteration, filename, new_content)
                        for fp in args.files:
                            if Path(fp).name == filename:
                                Path(fp).write_text(new_content)
                                break

                        old_lines = old_content.count('\n') + 1
                        new_lines = new_content.count('\n') + 1
                        logger.info(f"Updated {filename}: {applied} applied, {failed} failed "
                                    f"({old_lines} → {new_lines} lines)")
                        logger.event("file_updated", iteration=iteration, filename=filename,
                                     old_lines=old_lines, new_lines=new_lines,
                                     old_size=len(old_content), new_size=len(new_content),
                                     patches_applied=applied, patches_failed=failed)
                    else:
                        logger.warn(f"No patches applied to {filename} ({failed} failed)")

                if not files_updated:
                    # Fallback: try legacy full-file extraction
                    logger.info("No SEARCH/REPLACE blocks applied, trying full-file fallback...")
                    for filename in list(files_content.keys()):
                        new_code = extract_code_from_response(fix_response, filename)
                        if new_code and len(new_code.strip()) > 100:
                            old_len = len(files_content[filename])
                            new_len = len(new_code)
                            if new_len >= old_len * 0.5:
                                files_content[filename] = new_code
                                files_updated = True
                                storage.save_iteration_file(iteration, filename, new_code)
                                for fp in args.files:
                                    if Path(fp).name == filename:
                                        Path(fp).write_text(new_code)
                                        break
                                logger.info(f"Fallback: updated {filename} ({old_len} → {new_len} chars, "
                                            f"{files_content[filename].count(chr(10))+1} → {new_code.count(chr(10))+1} lines)")

                    if not files_updated:
                        logger.warn("No files updated, breaking loop")
                        break
            else:
                # No SEARCH/REPLACE blocks found — try legacy extraction
                logger.info("No SEARCH/REPLACE blocks found, trying full-file extraction...")
                files_updated = False
                for filename in list(files_content.keys()):
                    new_code = extract_code_from_response(fix_response, filename)
                    if new_code and len(new_code.strip()) > 100:
                        old_len = len(files_content[filename])
                        new_len = len(new_code)
                        if new_len >= old_len * 0.5:
                            files_content[filename] = new_code
                            files_updated = True
                            storage.save_iteration_file(iteration, filename, new_code)
                            for fp in args.files:
                                if Path(fp).name == filename:
                                    Path(fp).write_text(new_code)
                                    break
                            old_lines = files_content[filename].count('\n') + 1
                            new_lines = new_code.count('\n') + 1
                            logger.info(f"Updated {filename} ({old_lines} → {new_lines} lines)")

                if not files_updated:
                    logger.warn("No files updated, breaking loop")
                    break

            # ── Step 7: Diff verification ──
            if verifier_t1 and files_updated:
                # Generate diff between pre-fix and post-fix content
                for filename in list(files_content.keys()):
                    pre_fix = last_good_files.get(filename, "")
                    post_fix = files_content[filename]
                    if pre_fix != post_fix:
                        diff_text = generate_diff(pre_fix, post_fix, filename)
                        if diff_text:
                            bad_verdicts = run_diff_verification(
                                client, verifier_t1, diff_text, findings_text,
                                task_context, iteration, storage, logger, model_stats
                            )
                            if bad_verdicts:
                                logger.warn(f"Verifier found {len(bad_verdicts)} bad fix(es), reverting")
                                # Revert to pre-fix state
                                files_content = {name: content for name, content in last_good_files.items()}
                                for fn, content in files_content.items():
                                    for fp in args.files:
                                        if Path(fp).name == fn:
                                            Path(fp).write_text(content)
                                            break
                                logger.event("revert", iteration=iteration,
                                             reason="verifier rejected fixes",
                                             bad_verdicts=len(bad_verdicts))
                                files_updated = False
                                break

            if not files_updated:
                # Was reverted by verifier — skip tests, continue to next iteration
                print("   🔄 Reverted by verifier, continuing...")
                continue

            # Verification passed — update last known good state
            last_good_files = {name: content for name, content in files_content.items()}

            # ── Step 8: Post-fix tests ──
            if test_cmd and config["test"]["after_fix"]:
                logger.info("Running post-fix tests...")
                test_ok, test_out = run_tests(test_cmd)
                storage.save_test_output(iteration, "post", test_ok, test_out)
                logger.event("test_run", iteration=iteration, phase="post", passed=test_ok)
                if test_ok:
                    print("   ✅ Post-fix tests pass")
                    # Update last known good state
                    last_good_files = {name: content for name, content in files_content.items()}
                    logger.info("Snapshot saved as last known good state")
                else:
                    print(f"   ❌ Post-fix tests failed — reverting to last good version")
                    logger.warn("Tests failed after fix, reverting to last good state",
                                test_output=test_out[:500])

                    # Revert files to last known good state
                    files_content = {name: content for name, content in last_good_files.items()}
                    for filename, content in files_content.items():
                        for fp in args.files:
                            if Path(fp).name == filename:
                                Path(fp).write_text(content)
                                break
                    storage.save_iteration_file(iteration, "REVERTED", "Reverted to last good state")
                    logger.event("revert", iteration=iteration, reason="post-fix tests failed")

        except Exception as e:
            # Retry once for transient errors (401, 403, 429, timeouts)
            retry_codes = ("401", "403", "429", "timeout", "Connection")
            if any(code in str(e) for code in retry_codes):
                logger.warn(f"Coder failed (retrying in 10s): {e}")
                print(f"   ⚠️  Coder failed — retrying in 10s...")
                time.sleep(10)
                try:
                    fix_response, fix_usage = client.call(
                        coder_provider, coder_model, fix_messages, max_tokens=16384, timeout=600
                    )
                    storage.save_fix_response(iteration, fix_response)
                    blocks = parse_search_replace_blocks(fix_response)
                    if blocks:
                        files_updated = False
                        for filename in list(files_content.keys()):
                            old_content = files_content[filename]
                            new_content, applied, failed = apply_search_replace(
                                old_content, blocks, logger
                            )
                            if applied > 0:
                                files_content[filename] = new_content
                                files_updated = True
                                storage.save_iteration_file(iteration, filename, new_content)
                                for fp in args.files:
                                    if Path(fp).name == filename:
                                        Path(fp).write_text(new_content)
                                        break
                                old_lines = old_content.count('\n') + 1
                                new_lines = new_content.count('\n') + 1
                                print(f"   ✅ {filename}: {applied} applied, {failed} failed "
                                      f"({old_lines} → {new_lines} lines) [retry]")
                        if files_updated:
                            last_good_files = {name: content for name, content in files_content.items()}
                            storage.save_checkpoint(iteration, files_content, model_stats,
                                                    addressed_fingerprints, last_good_files)
                            print()
                            continue
                except Exception as e2:
                    logger.error(f"Coder retry failed: {e2}")
                    print(f"   ❌ Coder retry failed: {e2}")

            logger.error(f"Coder failed: {e}")
            storage.save_fix_response(iteration, f"ERROR: {e}")
            # Save checkpoint before halting so we can resume
            storage.save_checkpoint(iteration, files_content, model_stats,
                                    addressed_fingerprints, last_good_files)
            logger.info(f"Checkpoint saved at iteration {iteration} (coder failed)")
            print(f"\n   💾 Checkpoint saved — resume with: --resume {storage.run_dir}")
            break

        # Save checkpoint after each successful iteration
        storage.save_checkpoint(iteration, files_content, model_stats,
                                addressed_fingerprints, last_good_files)

        print()

    # ── Final Summary ──
    elapsed = time.time() - start_time
    summary = {
        "version": VERSION,
        "task": str(task_path),
        "files": list(files_content.keys()),
        "iterations": iteration,
        "elapsed_seconds": round(elapsed, 1),
        "model_stats": model_stats,
        "run_dir": str(storage.run_dir),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    storage.save_summary(summary)
    logger.event("run_complete", **summary)
    logger.close()

    print()
    print("=" * 60)
    print(f"  NEURON-LOOP COMPLETE")
    print(f"  Iterations:  {iteration}")
    print(f"  Elapsed:     {elapsed:.0f}s")
    print(f"  Run dir:     {storage.run_dir}")
    print()
    print("  Model Stats:")
    for label, stats in model_stats.items():
        print(f"    {label}: {stats['total_findings']} findings, "
              f"{stats['api_calls']} calls, {stats['errors']} errors")
    print("=" * 60)


if __name__ == "__main__":
    main()
