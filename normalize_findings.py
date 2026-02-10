#!/usr/bin/env python3
"""
Findings Normalizer for TQUIC Kernel Audit.
Reads all Claude-generated .md audit files and produces a normalized claude.json.
"""

import json
import re
import os
import glob

# Files to EXCLUDE (not from Claude Opus/Sonnet)
EXCLUDE_FILES = {
    "AUDIT_CODEX.md",       # OpenAI Codex
    "FINDINGS_SUMMARY.md",  # Summary/aggregation, not raw audit
    "codex.json",
    "gemini_findings.json",
}

def detect_model(content, filename):
    """Detect whether a file is from Claude Opus or Sonnet."""
    content_lower = content.lower()
    if "codex" in filename.lower() and "claude" not in content_lower:
        return None  # Not Claude
    if "claude opus 4.6" in content_lower or "claude-opus-4-6" in content_lower or "opus 4.6" in content_lower:
        return "opus"
    if "claude sonnet" in content_lower or "sonnet" in content_lower:
        return "sonnet"
    # Default: if it has kernel security reviewer patterns and date 2026-02-09, it's Claude
    if "kernel security reviewer" in content_lower or "security reviewer" in content_lower:
        return "opus"  # All these audits were done by Opus 4.6
    if "2026-02-09" in content or "2026-02-10" in content:
        return "opus"  # Same audit session
    return None


def map_severity(sev_str):
    """Map various severity strings to S0-S3."""
    sev = sev_str.strip().upper()
    if sev in ("CRITICAL", "CRIT", "P0"):
        return "S0"
    elif sev in ("HIGH", "P1"):
        return "S1"
    elif sev in ("MEDIUM", "MED", "P2"):
        return "S2"
    elif sev in ("LOW", "INFORMATIONAL", "INFO", "P3"):
        return "S3"
    return "S2"  # default conservative


def map_category(title, desc, file_context):
    """Infer category from finding content."""
    text = (title + " " + desc + " " + file_context).lower()
    if any(w in text for w in ["buffer overflow", "stack overflow", "heap overflow", "out-of-bounds", "oob read", "oob write", "memcpy", "bounds check"]):
        return "memory"
    if any(w in text for w in ["use-after-free", "uaf", "double-free", "freed memory", "dangling pointer", "reference count", "refcount"]):
        return "memory"
    if any(w in text for w in ["race condition", "toctou", "deadlock", "lock", "spin_lock", "concurrent", "atomic", "data race"]):
        return "concurrency"
    if any(w in text for w in ["integer overflow", "integer underflow", "truncation", "wrap", "overflow in"]):
        return "correctness"
    if any(w in text for w in ["ssrf", "namespace escape", "privilege", "capability", "cap_net_admin", "authentication", "authorization"]):
        return "security"
    if any(w in text for w in ["crypto", "aead", "key", "nonce", "tls", "certificate", "ocsp", "hmac", "encryption", "decrypt"]):
        return "security"
    if any(w in text for w in ["dos", "denial of service", "resource exhaustion", "memory exhaustion", "cpu exhaustion", "infinite loop"]):
        return "security"
    if any(w in text for w in ["rfc", "protocol", "compliance", "violation", "quic v2"]):
        return "correctness"
    if any(w in text for w in ["performance", "cache line", "allocation", "hot path", "latency", "throughput"]):
        return "perf"
    if any(w in text for w in ["api", "interface", "socket option", "setsockopt"]):
        return "api"
    if any(w in text for w in ["build", "compile", "makefile", "kconfig"]):
        return "build"
    if any(w in text for w in ["test", "kunit", "selftest"]):
        return "tests"
    return "correctness"


def extract_file_paths(text):
    """Extract file paths from finding text."""
    paths = set()
    # Match paths like net/tquic/... or /Users/.../net/tquic/...
    for m in re.finditer(r'(?:/Users/[^\s`\'"]+/)?(?:net/(?:tquic|quic)/[^\s`\'",:)]+)', text):
        p = m.group()
        # Normalize to relative path
        if "/Users/" in p:
            idx = p.find("net/")
            if idx >= 0:
                p = p[idx:]
        paths.add(p)
    return list(paths)


def extract_symbols(text):
    """Extract function/symbol names from finding text."""
    symbols = set()
    # Match function names like func_name()
    for m in re.finditer(r'`?(\w{3,}_\w+)\(\)`?', text):
        symbols.add(m.group(1))
    # Match struct names
    for m in re.finditer(r'struct\s+(\w+)', text):
        symbols.add(m.group(1))
    return list(symbols)[:10]  # cap at 10


def extract_line_ranges(text, file_paths):
    """Extract line ranges from finding text."""
    ranges = []
    for m in re.finditer(r'[Ll]ines?[:\s]+~?(\d+)(?:\s*[-–]\s*(\d+))?', text):
        start = m.group(1)
        end = m.group(2) or start
        if file_paths:
            ranges.append(f"{file_paths[0]}:{start}-{end}")
        else:
            ranges.append(f":{start}-{end}")
    return ranges[:5]


def extract_snippets(text):
    """Extract code snippets from finding text."""
    snippets = []
    for m in re.finditer(r'```(?:c)?\n(.*?)\n```', text, re.DOTALL):
        snippet = m.group(1).strip()
        if len(snippet) > 20 and len(snippet) < 500:
            snippets.append(snippet[:300])
    return snippets[:3]


def parse_findings_from_md(content, source_file):
    """Parse findings from a markdown audit file."""
    findings = []

    # Split into sections by heading patterns
    # Look for patterns like ### C-1:, ### CRIT-01:, ### HIGH-01:, ### 1.1 CRITICAL:, etc.
    heading_pattern = re.compile(
        r'^###\s+'
        r'(?:'
        r'(?:CRITICAL|CRIT|C|HIGH|H|MEDIUM|MED|M|LOW|L|INFO|I)'
        r'[-_]?\d+[a-z]?'
        r'|'
        r'(?:\d+\.?\d*\s+)?'
        r'(?:CRITICAL|HIGH|MEDIUM|LOW)'
        r')'
        r'[:\s]',
        re.MULTILINE | re.IGNORECASE
    )

    # Also match patterns like "### CRITICAL-B1:", "### HIGH-F1:", etc.
    heading_pattern2 = re.compile(
        r'^###\s+'
        r'(?:CRITICAL|CRIT|HIGH|MEDIUM|MED|LOW)'
        r'[-_]?[A-Z]?\d+[a-z]?'
        r'[:\s]',
        re.MULTILINE | re.IGNORECASE
    )

    # Combined pattern
    combined_pattern = re.compile(
        r'^###\s+((?:CRITICAL|CRIT|C|HIGH|H|MEDIUM|MED|M|LOW|L)[-_]?(?:[A-Z]?\d+[a-z]?)?)\s*[:.]\s*(.*?)$',
        re.MULTILINE | re.IGNORECASE
    )

    # Alternative: section headers with severity in brackets like [P0], [P1]
    bracket_pattern = re.compile(
        r'^###\s+\[(P[0-3])\]\s*(.*?)$',
        re.MULTILINE
    )

    # Also match numbered findings like "### 1.1 CRITICAL: ..."
    numbered_pattern = re.compile(
        r'^###\s+(?:\d+\.?\d*\s+)?(CRITICAL|HIGH|MEDIUM|LOW)\s*[:.]\s*(.*?)$',
        re.MULTILINE | re.IGNORECASE
    )

    # Match "### Bug N:" pattern (EXTREME_CODE_REVIEW.md)
    bug_pattern = re.compile(
        r'^###\s+Bug\s+(\d+)\s*[:.]\s*(.*?)$',
        re.MULTILINE | re.IGNORECASE
    )

    # Match "### UAF-P1-01 [CRITICAL]" pattern
    uaf_pattern = re.compile(
        r'^###\s+(UAF-[A-Z0-9-]+)\s+\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*[-–—]\s*(.*?)$',
        re.MULTILINE | re.IGNORECASE
    )

    # Match "**Finding MEM-1 (MEDIUM)**" pattern (inline findings)
    inline_finding_pattern = re.compile(
        r'\*\*Finding\s+([A-Z]+-\d+)\s+\((CRITICAL|HIGH|MEDIUM|LOW)\)\*\*\s*[:.]\s*(.*?)$',
        re.MULTILINE | re.IGNORECASE
    )

    # Match "#### CRITICAL-01:" or "#### HIGH:" etc. with finding text
    h4_pattern = re.compile(
        r'^####\s+((?:CRITICAL|HIGH|MEDIUM|LOW)[-_]?\d*)\s*[:.]\s*(.*?)$',
        re.MULTILINE | re.IGNORECASE
    )

    sections = []

    # Find all heading matches
    for pattern in [combined_pattern, bracket_pattern, numbered_pattern]:
        for m in pattern.finditer(content):
            sev_id = m.group(1)
            title = m.group(2).strip() if m.lastindex >= 2 else ""
            start = m.start()
            sections.append((start, sev_id, title))

    # Bug pattern (EXTREME_CODE_REVIEW.md)
    for m in bug_pattern.finditer(content):
        bug_num = m.group(1)
        title = m.group(2).strip()
        start = m.start()
        # Look ahead for severity in text
        text_after = content[start:start+500]
        sev = "MEDIUM"
        if "**Severity:** CRITICAL" in text_after or "**CRITICAL**" in text_after:
            sev = "CRITICAL"
        elif "**Severity:** HIGH" in text_after or "**HIGH**" in text_after:
            sev = "HIGH"
        elif "**Severity:** MEDIUM" in text_after:
            sev = "MEDIUM"
        elif "**Severity:** LOW" in text_after:
            sev = "LOW"
        # Also check the summary table
        for line in content.split('\n'):
            if f"| {bug_num} |" in line or f"| {bug_num} " in line:
                if "CRITICAL" in line:
                    sev = "CRITICAL"
                elif "HIGH" in line:
                    sev = "HIGH"
                elif "MEDIUM" in line:
                    sev = "MEDIUM"
                elif "LOW" in line:
                    sev = "LOW"
        sections.append((start, sev, title))

    # UAF pattern
    for m in uaf_pattern.finditer(content):
        uaf_id = m.group(1)
        sev = m.group(2)
        title = m.group(3).strip()
        start = m.start()
        sections.append((start, sev, f"{uaf_id}: {title}"))

    # Inline finding pattern
    for m in inline_finding_pattern.finditer(content):
        fid = m.group(1)
        sev = m.group(2)
        title = m.group(3).strip()
        start = m.start()
        sections.append((start, sev, f"{fid}: {title}"))

    # h4 pattern for section-based findings
    for m in h4_pattern.finditer(content):
        sev = m.group(1)
        title = m.group(2).strip()
        start = m.start()
        sections.append((start, sev, title))

    # Sort by position and deduplicate nearby matches
    sections.sort(key=lambda x: x[0])
    deduped = []
    for s in sections:
        if not deduped or abs(s[0] - deduped[-1][0]) > 10:
            deduped.append(s)
    sections = deduped

    # Extract content for each section
    for i, (start, sev_id, title) in enumerate(sections):
        end = sections[i + 1][0] if i + 1 < len(sections) else len(content)
        section_text = content[start:end]

        # Determine severity
        sev_str = sev_id.upper()
        if sev_str.startswith("P"):
            severity = {"P0": "S0", "P1": "S1", "P2": "S2", "P3": "S3"}.get(sev_str, "S2")
        elif any(sev_str.startswith(p) for p in ["CRITICAL", "CRIT", "C"]):
            severity = "S0"
        elif any(sev_str.startswith(p) for p in ["HIGH", "H"]):
            severity = "S1"
        elif any(sev_str.startswith(p) for p in ["MEDIUM", "MED", "M"]):
            severity = "S2"
        elif any(sev_str.startswith(p) for p in ["LOW", "L"]):
            severity = "S3"
        else:
            severity = "S2"

        # Check if severity is overridden in text
        if "**Severity:** CRITICAL" in section_text or "**Severity:** S0" in section_text:
            severity = "S0"
        elif "**Severity:** HIGH" in section_text:
            severity = "S1"
        elif "**Severity:** MEDIUM" in section_text:
            severity = "S2"
        elif "**Severity:** LOW" in section_text:
            severity = "S3"

        if not title:
            # Try to extract from heading line
            heading_match = re.match(r'^###\s+.*?[:.]\s*(.*?)$', section_text, re.MULTILINE)
            if heading_match:
                title = heading_match.group(1).strip()

        # Clean title
        title = re.sub(r'^[:\s]+', '', title)
        title = re.sub(r'\s*\(.*?\)\s*$', '', title)  # Remove trailing parens
        if not title:
            title = f"Finding from {source_file}"

        # Extract description
        desc_match = re.search(r'\*\*Description\*\*[:\s]*(.*?)(?=\n\*\*|\n###|\Z)', section_text, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else ""
        if not description:
            # Use first paragraph after heading
            lines = section_text.split('\n')
            desc_lines = []
            started = False
            for line in lines[1:]:  # Skip heading
                if line.strip() and not line.startswith('#') and not line.startswith('|'):
                    started = True
                    desc_lines.append(line.strip())
                elif started and not line.strip():
                    break
            description = ' '.join(desc_lines)[:500]

        # Extract impact
        impact_match = re.search(r'\*\*Impact\*\*[:\s]*(.*?)(?=\n\*\*|\n###|\Z)', section_text, re.DOTALL)
        impact = impact_match.group(1).strip() if impact_match else ""
        if not impact:
            impact = description[:200] if description else "See description"

        # Extract recommendation/fix
        fix_match = re.search(r'\*\*(?:Recommendation|Fix|Recommended fix)\*\*[:\s]*(.*?)(?=\n\*\*|\n###|\n---|\Z)', section_text, re.DOTALL)
        fix = fix_match.group(1).strip() if fix_match else ""
        if not fix:
            fix_match = re.search(r'\*\*Fix\*\*[:\s]*(.*?)(?=\n\*\*|\n###|\n---|\Z)', section_text, re.DOTALL)
            fix = fix_match.group(1).strip() if fix_match else ""

        # Extract evidence
        file_paths = extract_file_paths(section_text)
        symbols = extract_symbols(section_text)
        line_ranges = extract_line_ranges(section_text, file_paths)
        snippets = extract_snippets(section_text)

        # Determine category
        category = map_category(title, description + " " + section_text[:500], source_file)

        # Root cause
        root_cause_match = re.search(r'\*\*(?:Root Cause|Vulnerability|Vulnerable Code)\*\*[:\s]*(.*?)(?=\n\*\*|\n###|\Z)', section_text, re.DOTALL)
        root_cause = root_cause_match.group(1).strip()[:300] if root_cause_match else ""
        if not root_cause:
            root_cause = description[:300] if description else title

        findings.append({
            "sev_id": sev_id,
            "title": title[:200],
            "severity": severity,
            "category": category,
            "description": description[:1000],
            "impact": impact[:500],
            "fix": fix[:500],
            "file_paths": file_paths,
            "symbols": symbols,
            "line_ranges": line_ranges,
            "snippets": snippets,
            "root_cause": root_cause[:500],
            "source_file": source_file,
        })

    return findings


def normalize_to_finding_card(findings, repo_name="tquic-kernel"):
    """Convert parsed findings to FindingCard JSON schema."""
    cards = []
    for i, f in enumerate(findings):
        fid = f"F-{i+1:03d}"
        card = {
            "id": fid,
            "title": f["title"],
            "category": f["category"],
            "severity": f["severity"],
            "confidence": "high" if f["severity"] in ("S0", "S1") else "medium",
            "impact": f["impact"] if f["impact"] else "See description in notes",
            "evidence": {
                "file_paths": f["file_paths"],
                "symbols": f["symbols"],
                "line_ranges": f["line_ranges"],
                "snippets": f["snippets"],
                "logs_or_errors": []
            },
            "repro": {
                "steps": [],
                "expected": "",
                "actual": ""
            },
            "root_cause_hypothesis": f["root_cause"],
            "fix_suggestion": f["fix"] if f["fix"] else "See original report for recommendation",
            "tests_to_add": [],
            "dependencies": [],
            "notes": f"Source: {f['source_file']}. Original finding ID: {f['sev_id']}."
        }

        # Add confidence notes
        if not f["file_paths"]:
            card["notes"] += " Note: file paths not explicitly specified in finding."
        if not f["snippets"]:
            card["notes"] += " Note: no code snippets provided in original finding."
        if not f["fix"]:
            card["notes"] += " Note: no explicit fix suggestion in original finding."

        cards.append(card)

    return cards


def main():
    findings_dir = "/workspace/llm findings"
    all_findings = []
    file_model_map = {}

    md_files = sorted(glob.glob(os.path.join(findings_dir, "*.md")))

    for filepath in md_files:
        filename = os.path.basename(filepath)
        if filename in EXCLUDE_FILES:
            print(f"SKIP (excluded): {filename}")
            continue

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        model = detect_model(content, filename)
        if model is None:
            print(f"SKIP (not Claude): {filename}")
            continue

        file_model_map[filename] = model
        print(f"PROCESSING ({model}): {filename}")

        findings = parse_findings_from_md(content, filename)
        print(f"  Found {len(findings)} findings")
        all_findings.extend(findings)

    print(f"\nTotal findings extracted: {len(all_findings)}")
    print(f"Files processed: {len(file_model_map)}")
    for fname, model in sorted(file_model_map.items()):
        print(f"  {model}: {fname}")

    # Normalize to FindingCard schema
    cards = normalize_to_finding_card(all_findings)

    # Write output
    output_path = os.path.join(findings_dir, "claude.json")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(cards, f, indent=2, ensure_ascii=False)

    print(f"\nOutput written to: {output_path}")
    print(f"Total FindingCards: {len(cards)}")

    # Summary by severity
    sev_counts = {}
    for c in cards:
        sev_counts[c["severity"]] = sev_counts.get(c["severity"], 0) + 1
    print("\nSeverity distribution:")
    for s in sorted(sev_counts.keys()):
        print(f"  {s}: {sev_counts[s]}")

    # Summary by category
    cat_counts = {}
    for c in cards:
        cat_counts[c["category"]] = cat_counts.get(c["category"], 0) + 1
    print("\nCategory distribution:")
    for cat in sorted(cat_counts.keys()):
        print(f"  {cat}: {cat_counts[cat]}")


if __name__ == "__main__":
    main()
