# Lessons Learned — Neuron-Loop v0.5.0

From running the loop on 8 Thunderstorm Collector scripts (March 2026).

---

## 1. Code Bloat — The Coder Adds More Than It Fixes

**Problem**: The coder model adds defensive code, verbose error handling, and new features to address reviewer findings. Each fix makes the file bigger. Bigger file → more surface area → more findings → more fixes → bloat spiral. BAT went from 390 → 571 lines in 3 iterations.

**Root cause**: The coder prompt says "fix each finding" but doesn't say "don't add unnecessary code." The reviewer prompt flags edge cases as MEDIUM, the coder adds 20 lines of handling per edge case.

**Fix needed**:
- Add a **bloat guard** in the coder prompt: "Prefer deleting code over adding code. If a fix requires more than 10 lines, explain why."
- Add a **line growth limit** in config (e.g., `max_growth_percent: 20`). If the coder's changes grow the file by more than 20%, warn and consider reverting.
- Add a **WONT_FIX / LIMITATION** option to the coder: findings that can't be fixed cleanly in the target language should be marked as known limitations, not hacked around.

---

## 2. Language Purity — The Coder Reaches for the Wrong Tool

**Problem**: The coder added 7 PowerShell calls inside a .bat file. This defeats the purpose — if PowerShell were available, the user would run the .ps1 collector. The reviewer prompt didn't flag this because it wasn't told to check for it.

**Root cause**: Neither the reviewer nor coder prompts have language-purity constraints. The coder sees "I need to parse JSON in batch" and reaches for PowerShell because it's the obvious solution.

**Fix needed**:
- The **reviewer prompt** should include a "Language purity" check: "Flag any call to an external language runtime as CRITICAL."
- The **coder prompt** should include hard constraints: "You are writing {language}. Do NOT call other languages (Python, PowerShell, Perl, etc.). If a feature is impossible in the target language, respond with WONT_FIX and explain the limitation."
- These constraints should come from the **task file**, not be hardcoded — different projects have different rules.

---

## 3. WONT_FIX / Known Limitations — No Graceful Exit

**Problem**: When a reviewer flags something that genuinely can't be fixed in the target language (e.g., "no signal handling in batch"), the coder tries to hack around it anyway. This adds complexity, often introduces bugs, and never fully solves the problem.

**Root cause**: The coder's only options are FIXED, SKIPPED, or PARTIAL. There's no WONT_FIX that says "this is a known platform limitation." Findings marked SKIPPED just come back next iteration.

**Fix needed**:
- Add **WONT_FIX** as a valid coder response: "This is a known limitation of {language}. Cannot be fixed without introducing external dependencies."
- WONT_FIX findings should be **permanently suppressed** (added to `addressed_fingerprints`) so they don't resurface.
- At the end of the run, collect all WONT_FIX items into a **limitations section** in the report.
- Optionally: auto-add to a project's README or LIMITATIONS.md.

---

## 4. Reviewer Doesn't Catch Coder Bugs

**Problem**: The coder introduced a variable scoping bug in the batch retry logic (`!_CURL!` vs `%_CURL%` across SETLOCAL boundaries). This survived 15 iterations without being caught by any reviewer.

**Root cause**: Reviewers review the whole file each iteration, but they don't specifically scrutinize the coder's recent changes. They also lack domain-specific knowledge (batch SETLOCAL scoping is obscure).

**Fix needed**:
- The **reviewer prompt** should include the diff from the previous iteration: "The following changes were made in the last iteration. Review them specifically for regressions."
- Consider a **regression-focused review** mode: show the reviewer ONLY the diff, ask specifically "did this change introduce any bugs?"
- The existing **verifier** step does this partially, but it only checks if fixes address the reported findings — it doesn't look for NEW bugs introduced by the fix.

---

## 5. Addressed Findings Resurface

**Problem**: The dedup/fingerprinting system uses finding titles and locations, but reviewers describe the same issue differently across iterations. A finding marked as "addressed" comes back with a slightly different title and gets flagged again.

**Root cause**: Fingerprinting is string-based (`hash(severity + title + location)`). Reviewers don't use consistent naming.

**Fix needed**:
- Use **semantic similarity** for dedup, not exact hash matching.
- Or: include the **code region** in the fingerprint (hash the actual code at the reported location), so if the code hasn't changed, the finding is suppressed regardless of how it's described.

---

## 6. No "Review-Only Then Fix Selectively" Workflow

**Problem**: For mature code that's already been through the loop, running the full review-fix cycle is counterproductive. What's needed is: review all scripts, produce a report, then let a human decide which findings to fix.

**Root cause**: `--review-only` exists but only runs 1 iteration and stops. There's no workflow for "review all files, produce consolidated report, then selectively fix."

**Fix needed**:
- Add a **`--review-report`** mode: runs reviewers on all files, produces a consolidated findings report (grouped by severity), and writes it to a markdown file. No coder involvement.
- Add a **`--fix-findings F1,F3,F7`** mode: takes a previous review report and tells the coder to fix only specific findings by ID.
- This gives humans control over which findings are worth the code churn.

---

## Priority for v0.6.0

1. **WONT_FIX support** (§3) — stops the biggest source of waste
2. **Bloat guard** (§1) — line growth limit + coder prompt update
3. **Coder constraints from task file** (§2) — language purity, no-external-deps
4. **Review-report mode** (§6) — for mature code
5. **Diff-aware reviewer** (§4) — show coder's changes to reviewer
6. **Semantic dedup** (§5) — nice to have but lower priority
