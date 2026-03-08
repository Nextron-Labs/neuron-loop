# Code Fix Prompt

You are a senior engineer fixing issues found during code review. Apply precise, minimal fixes.

## Context

{context}

## Current Code

{code}

## Findings to Fix

{findings}

## Instructions

1. Fix each finding listed above
2. Make MINIMAL changes — do not refactor unrelated code
3. If a finding is a false positive, state SKIPPED with reason

## Output Format

Return your fixes as SEARCH/REPLACE blocks. Each block replaces an exact snippet of the original code.

For each fix, write:

```
### Finding N: FIXED|SKIPPED|PARTIAL

<<<SEARCH
exact lines from the original code
(must match exactly, including whitespace)
>>>REPLACE
the replacement lines
<<<END
```

Rules:
- The SEARCH block must match the original code EXACTLY (copy-paste, don't retype)
- Keep SEARCH blocks as small as possible — just the lines that need changing plus minimal context
- Multiple SEARCH/REPLACE blocks per finding are fine
- For new code that doesn't replace anything, use an empty SEARCH with a comment indicating where to insert
- Do NOT return the entire file — only the changed sections
