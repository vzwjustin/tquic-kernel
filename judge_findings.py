#!/usr/bin/env python3
"""
Skeptical Code Audit Judge for TQUIC Kernel Findings.

Reads the MASTER_BUG_LEDGER.md and MASTER_BUG_LEDGER.json (the two master
files produced by consolidate_findings.py) and produces a judged report.

For each ConsolidatedFinding the judge performs:
  1) Evidence check   – concrete file path + symbol + line range/snippet/log?
  2) Plausibility check – does the claim make sense for C/kernel code?
  3) Contradiction check – do sources disagree? which is best-evidenced?
  4) Verification plan  – minimum commands to confirm/deny
  5) Fix safety         – safest fix strategy + regression guard

Outputs:
  - JUDGED_FINDINGS.md   (Markdown table + per-finding detail)
  - JUDGED_FINDINGS.json  (machine-readable array of JudgedFinding objects)
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEV_ORDER = {"S0": 0, "S1": 1, "S2": 2, "S3": 3}

VERDICT_ORDER = {"CERTIFIED": 0, "PLAUSIBLE": 1, "SPECULATIVE": 2, "REJECTED": 3}

# Generic / boilerplate fix text that signals the finding lacked a real fix.
GENERIC_FIX_PHRASES = [
	"see original report",
	"implement an rfc-compliant correction",
	"add targeted regression coverage",
]

# False-positive-prone title keywords for specific categories.
RACE_FP_KEYWORDS = {"race", "concurrent", "locking", "deadlock", "atomic"}
MEMORY_FP_KEYWORDS = {"overflow", "underflow", "oob", "use-after-free", "uaf", "double-free"}

# Snippet quality: if snippet is just a comment, it's weak.
COMMENT_ONLY_RE = re.compile(r"^\s*(?://|/\*|\*)", re.MULTILINE)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class JudgedFinding:
	cid: str
	title: str
	category: str
	severity: str
	original_confidence: str
	priority_score: float
	source_count: int
	sources: list[str]

	# Judging results
	verdict: str  # CERTIFIED | PLAUSIBLE | SPECULATIVE | REJECTED
	confidence_after_judging: str  # high | medium | low
	reason: list[str]  # 2-5 bullet points
	key_evidence_present: str  # terse summary of what evidence exists
	whats_missing: list[str]  # explicit gaps
	minimal_verification: list[str]  # concrete commands/steps
	safest_fix: str  # fix recommendation
	required_next_artifacts: list[str]  # exact file+line, logs, failing test, etc.


# ---------------------------------------------------------------------------
# Evidence scoring helpers
# ---------------------------------------------------------------------------

def has_concrete_file(ev: dict[str, Any]) -> bool:
	"""True if at least one real file path is present."""
	for p in ev.get("file_paths", []):
		if p and p != "unknown_file" and "/" in p:
			return True
	return False


def has_line_ranges(ev: dict[str, Any]) -> bool:
	"""True if at least one line range with numbers is present."""
	for lr in ev.get("line_ranges", []):
		if lr and re.search(r":\d+-\d+", lr):
			return True
	return False


def has_snippets(ev: dict[str, Any]) -> bool:
	"""True if at least one real code snippet (not just comments) exists."""
	for s in ev.get("snippets", []):
		if not s or len(s.strip()) < 15:
			continue
		# Check it's not purely comments
		lines = s.strip().split("\n")
		code_lines = [l for l in lines if l.strip() and not COMMENT_ONLY_RE.match(l)]
		if code_lines:
			return True
	return False


def has_symbols(ev: dict[str, Any]) -> bool:
	"""True if at least one meaningful symbol is present."""
	for s in ev.get("symbols", []):
		if s and s != "unknown_symbol" and len(s) > 3:
			return True
	return False


def has_logs(ev: dict[str, Any]) -> bool:
	"""True if logs/errors are present."""
	return bool(ev.get("logs_or_errors"))


def snippet_is_comment_only(ev: dict[str, Any]) -> bool:
	"""True if all snippets are comment-only (weak evidence)."""
	snippets = ev.get("snippets", [])
	if not snippets:
		return False
	for s in snippets:
		if not s:
			continue
		lines = s.strip().split("\n")
		code_lines = [l for l in lines if l.strip() and not COMMENT_ONLY_RE.match(l)]
		if code_lines:
			return False
	return True


def evidence_score(ev: dict[str, Any]) -> int:
	"""Score evidence strength from 0 (nothing) to 5 (comprehensive)."""
	score = 0
	if has_concrete_file(ev):
		score += 1
	if has_symbols(ev):
		score += 1
	if has_line_ranges(ev):
		score += 1
	if has_snippets(ev):
		score += 1
	if has_logs(ev):
		score += 1
	return score


def fix_is_generic(fix_text: str) -> bool:
	"""True if the recommended fix is boilerplate."""
	lower = fix_text.lower()
	return any(phrase in lower for phrase in GENERIC_FIX_PHRASES)


# ---------------------------------------------------------------------------
# Plausibility analysis
# ---------------------------------------------------------------------------

def plausibility_flags(cf: dict[str, Any]) -> list[str]:
	"""
	Identify common false-positive patterns.
	Returns a list of warning strings (empty = no flags).
	"""
	flags = []
	title_lower = cf["title"].lower()
	category = cf["category"].lower()
	ev = cf["merged_evidence"]

	# Race condition without shared-state evidence
	if category == "concurrency" or any(kw in title_lower for kw in RACE_FP_KEYWORDS):
		if not has_snippets(ev) and not has_line_ranges(ev):
			flags.append(
				"Race/locking claim without code snippet showing shared state "
				"or lock acquisition -- common false positive pattern."
			)

	# Memory safety claim without showing buffer/allocation
	if category == "memory" or any(kw in title_lower for kw in MEMORY_FP_KEYWORDS):
		if not has_snippets(ev):
			flags.append(
				"Memory safety claim without code snippet showing the "
				"vulnerable buffer/allocation."
			)

	# Snippet is comment-only
	if snippet_is_comment_only(ev):
		flags.append(
			"Snippet(s) contain only comments, not actual vulnerable code."
		)

	# Title is excessively long (often means it's pasted description, not a finding title)
	if len(cf["title"]) > 150:
		flags.append(
			"Title exceeds 150 chars -- may be a pasted description rather "
			"than a distilled finding."
		)

	# Single-source with S0 but no line ranges
	if cf["agreement"]["count"] == 1 and cf["severity"] == "S0":
		if not has_line_ranges(ev) and not has_snippets(ev):
			flags.append(
				"Single-source S0 finding with no line ranges or snippets -- "
				"severity may be inflated."
			)

	# Generic fix text
	if fix_is_generic(cf.get("recommended_fix", "")):
		flags.append(
			"Recommended fix is generic/boilerplate -- the reporter may not "
			"have understood the code deeply enough to propose a real fix."
		)

	# Unknown file + unknown symbol = very speculative
	pf = primary_file_from_ev(ev)
	ps = primary_symbol_from_ev(ev)
	if pf == "unknown_file" and ps == "unknown_symbol":
		flags.append(
			"No file path and no symbol identified -- finding is untethered "
			"to any specific code location."
		)

	return flags


# ---------------------------------------------------------------------------
# Contradiction analysis
# ---------------------------------------------------------------------------

def contradiction_notes(cf: dict[str, Any]) -> list[str]:
	"""Extract and interpret contradiction signals."""
	notes = []
	conflicts = cf.get("conflicts", [])

	for c in conflicts:
		if "severity disagreement" in c.lower():
			notes.append(f"Sources disagree on severity: {c}")
		elif "category disagreement" in c.lower():
			notes.append(f"Sources disagree on category: {c}")
		elif "single-source" in c.lower():
			notes.append("Single-source finding -- no independent confirmation.")
		elif "weakly evidenced" in c.lower():
			notes.append("Highest severity retained but flagged as weakly evidenced.")

	return notes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def primary_file_from_ev(ev: dict[str, Any]) -> str:
	for p in ev.get("file_paths", []):
		if p and p != "unknown_file":
			return p
	return "unknown_file"


def primary_symbol_from_ev(ev: dict[str, Any]) -> str:
	for s in ev.get("symbols", []):
		if s and s != "unknown_symbol" and len(s) > 3:
			return s
	return "unknown_symbol"


def build_evidence_summary(ev: dict[str, Any]) -> str:
	"""One-line summary of what evidence is present."""
	parts = []
	fp = ev.get("file_paths", [])
	sym = ev.get("symbols", [])
	lr = ev.get("line_ranges", [])
	sn = ev.get("snippets", [])
	lo = ev.get("logs_or_errors", [])

	if has_concrete_file(ev):
		parts.append(f"file:{len(fp)}")
	if has_symbols(ev):
		parts.append(f"sym:{len(sym)}")
	if has_line_ranges(ev):
		parts.append(f"lines:{len(lr)}")
	if has_snippets(ev):
		code_count = sum(1 for s in sn if s and len(s.strip()) >= 15)
		parts.append(f"snippet:{code_count}")
	if has_logs(ev):
		parts.append(f"log:{len(lo)}")

	if not parts:
		return "NONE"
	return ", ".join(parts)


def build_whats_missing(ev: dict[str, Any], cf: dict[str, Any]) -> list[str]:
	"""List exactly what evidence is absent."""
	missing = []

	if not has_concrete_file(ev):
		missing.append("Concrete source file path (e.g., net/tquic/...)")
	if not has_line_ranges(ev):
		missing.append("Exact line range(s) where the fault manifests")
	if not has_snippets(ev):
		missing.append("Code snippet proving the vulnerable pattern")
	elif snippet_is_comment_only(ev):
		missing.append("Code snippet with ACTUAL code (current snippets are comments only)")
	if not has_symbols(ev):
		missing.append("Function/struct symbol name at the fault site")
	if not has_logs(ev):
		missing.append("Kernel log / stack trace / error output demonstrating the issue")
	if cf["agreement"]["count"] < 2:
		missing.append("Independent confirmation from a second audit source")

	# Repro
	if cf.get("original_confidence", cf.get("confidence", "")) != "high":
		missing.append("Minimal reproduction steps (expected vs. actual)")

	return missing or ["No major evidence gaps."]


def build_verification_plan(
	cf: dict[str, Any], ev: dict[str, Any]
) -> list[str]:
	"""
	Build a minimal, targeted verification plan.
	Uses existing verification_commands as a base, then augments.
	"""
	cmds = []
	pf = primary_file_from_ev(ev)
	ps = primary_symbol_from_ev(ev)

	# If we have a concrete file, grep for the symbol in it
	if pf != "unknown_file" and ps != "unknown_symbol":
		cmds.append(f'rg -n "{ps}" "{pf}"')

	# If we have line ranges, show the exact lines
	for lr in ev.get("line_ranges", [])[:2]:
		m = re.match(r"([^:]+):(\d+)-(\d+)$", lr)
		if m:
			path, start, end = m.group(1), m.group(2), m.group(3)
			cmds.append(f"sed -n '{start},{end}p' {path}")

	# If no file, at least search for the symbol globally
	if pf == "unknown_file" and ps != "unknown_symbol":
		cmds.append(f'rg -rn "{ps}" net/tquic/')

	# Category-specific checks
	cat = cf.get("category", "").lower()
	if cat == "concurrency":
		if ps != "unknown_symbol":
			cmds.append(f'rg -n "spin_lock\\|mutex_lock\\|lock_sock" "{pf}"'
						if pf != "unknown_file"
						else f'rg -rn "spin_lock\\|mutex_lock" net/tquic/')
	elif cat == "memory":
		if pf != "unknown_file":
			cmds.append(f'rg -n "kmalloc\\|kzalloc\\|alloc_skb\\|memcpy" "{pf}"')

	# Build checks
	cmds.append("make M=net/tquic W=1")
	cmds.append("make M=net/tquic C=1  # sparse static analysis")

	# Dedupe
	seen = set()
	deduped = []
	for c in cmds:
		if c not in seen:
			seen.add(c)
			deduped.append(c)

	return deduped[:6]


def build_safest_fix(cf: dict[str, Any]) -> str:
	"""
	Produce a fix recommendation that prioritizes safety.
	Uses the existing recommended_fix if it's specific; otherwise synthesizes.
	"""
	rec = cf.get("recommended_fix", "").strip()
	risk = cf.get("risk_notes", "").strip()
	cat = cf.get("category", "").lower()

	# If the existing fix is specific (not generic), use it with a safety wrapper
	if rec and not fix_is_generic(rec):
		# Trim to first fix if there are multiple separated by " / "
		first_fix = rec.split(" / ")[0].strip()
		# Remove leading ** markdown artifacts
		first_fix = re.sub(r"^\*+\s*", "", first_fix)
		if len(first_fix) > 300:
			first_fix = first_fix[:297] + "..."
		safety = ""
		if risk:
			safety = f" Risk: {risk[:200]}"
		return f"{first_fix}{safety}"

	# Synthesize based on category
	if cat in ("memory", "security"):
		return (
			"Add bounds/lifetime validation at the identified code path; "
			"fail closed (-EINVAL/-ENOMEM) on malformed input. "
			"Guard with a KUnit test that sends boundary-condition packets."
		)
	if cat == "concurrency":
		return (
			"Audit the lock hierarchy for this code path; add missing "
			"lock acquisition or convert to lock-free design if contention "
			"is high. Validate under CONFIG_PROVE_LOCKING=y + lockdep."
		)
	if cat == "correctness":
		return (
			"Fix the protocol logic per the relevant RFC section; add an "
			"interop regression test covering the corrected state transition."
		)
	return (
		"Apply minimal targeted fix; add regression test; verify with "
		"make M=net/tquic W=1 C=1 and lockdep/KASAN enabled."
	)


# ---------------------------------------------------------------------------
# Core judging logic
# ---------------------------------------------------------------------------

def judge_finding(cf: dict[str, Any]) -> JudgedFinding:
	"""
	Apply the skeptical judge rubric to a single ConsolidatedFinding.
	"""
	ev = cf["merged_evidence"]
	src_count = cf["agreement"]["count"]
	sources = cf["agreement"]["sources"]
	severity = cf["severity"]
	orig_conf = cf["confidence"]

	# --- Evidence scoring ---
	escore = evidence_score(ev)
	has_file = has_concrete_file(ev)
	has_lines = has_line_ranges(ev)
	has_snip = has_snippets(ev)
	has_sym = has_symbols(ev)
	has_log = has_logs(ev)

	# --- Plausibility flags ---
	pf_flags = plausibility_flags(cf)

	# --- Contradiction signals ---
	contra_notes = contradiction_notes(cf)

	# --- Determine verdict ---
	verdict = _determine_verdict(
		escore=escore,
		src_count=src_count,
		severity=severity,
		has_file=has_file,
		has_lines=has_lines,
		has_snip=has_snip,
		has_sym=has_sym,
		pf_flags=pf_flags,
		contra_notes=contra_notes,
		cf=cf,
	)

	# --- Determine confidence after judging ---
	conf_after = _determine_confidence(
		verdict=verdict,
		escore=escore,
		src_count=src_count,
		has_file=has_file,
		has_lines=has_lines,
		has_snip=has_snip,
		pf_flags=pf_flags,
	)

	# --- Build reason bullets ---
	reason = _build_reason(
		cf=cf,
		ev=ev,
		escore=escore,
		src_count=src_count,
		verdict=verdict,
		pf_flags=pf_flags,
		contra_notes=contra_notes,
	)

	# --- Build required next artifacts ---
	whats_missing = build_whats_missing(ev, cf)
	next_artifacts = _build_next_artifacts(ev, cf, whats_missing)

	return JudgedFinding(
		cid=cf["cid"],
		title=cf["title"],
		category=cf["category"],
		severity=severity,
		original_confidence=orig_conf,
		priority_score=cf["priority_score"],
		source_count=src_count,
		sources=sources,
		verdict=verdict,
		confidence_after_judging=conf_after,
		reason=reason,
		key_evidence_present=build_evidence_summary(ev),
		whats_missing=whats_missing,
		minimal_verification=build_verification_plan(cf, ev),
		safest_fix=build_safest_fix(cf),
		required_next_artifacts=next_artifacts,
	)


def _determine_verdict(
	*,
	escore: int,
	src_count: int,
	severity: str,
	has_file: bool,
	has_lines: bool,
	has_snip: bool,
	has_sym: bool,
	pf_flags: list[str],
	contra_notes: list[str],
	cf: dict[str, Any],
) -> str:
	"""
	CERTIFIED  – strong evidence, multi-source, plausible
	PLAUSIBLE  – some evidence, makes sense, gaps remain
	SPECULATIVE – weak evidence, single source, or FP-prone
	REJECTED   – no evidence, contradicted, or clearly bogus
	"""
	# Heavy false-positive flags push toward SPECULATIVE
	severe_fp = len(pf_flags) >= 3

	# REJECTED: no evidence at all + single source + severe FP flags
	if escore == 0 and src_count == 1 and severe_fp:
		return "REJECTED"

	# REJECTED: no evidence at all + single source + generic fix
	if escore == 0 and src_count == 1 and fix_is_generic(cf.get("recommended_fix", "")):
		return "REJECTED"

	# CERTIFIED: 3-source agreement + file + (snippet OR line range)
	if src_count >= 3 and has_file and (has_snip or has_lines):
		if not severe_fp:
			return "CERTIFIED"
		return "PLAUSIBLE"  # demote if FP flags

	# CERTIFIED: 2-source + file + snippet + line range (comprehensive)
	if src_count >= 2 and has_file and has_snip and has_lines:
		if not severe_fp:
			return "CERTIFIED"
		return "PLAUSIBLE"

	# CERTIFIED: 3-source agreement + file + symbol (decent)
	if src_count >= 3 and has_file and has_sym:
		if len(pf_flags) <= 1:
			return "CERTIFIED"
		return "PLAUSIBLE"

	# PLAUSIBLE: file + (snippet OR line_range) with any source count
	if has_file and (has_snip or has_lines):
		return "PLAUSIBLE"

	# PLAUSIBLE: multi-source + file + symbol
	if src_count >= 2 and has_file and has_sym:
		return "PLAUSIBLE"

	# PLAUSIBLE: multi-source + snippet (even without file)
	if src_count >= 2 and has_snip:
		return "PLAUSIBLE"

	# PLAUSIBLE: single source but strong evidence
	if src_count == 1 and escore >= 3:
		return "PLAUSIBLE"

	# PLAUSIBLE: multi-source + symbol (file may be unknown)
	if src_count >= 2 and has_sym and escore >= 2:
		return "PLAUSIBLE"

	# SPECULATIVE: has some evidence but not enough for PLAUSIBLE
	if escore >= 1:
		return "SPECULATIVE"

	# SPECULATIVE: multi-source but zero evidence
	if src_count >= 2 and escore == 0:
		return "SPECULATIVE"

	# REJECTED: single source, no evidence
	if src_count == 1 and escore == 0:
		return "REJECTED"

	return "SPECULATIVE"


def _determine_confidence(
	*,
	verdict: str,
	escore: int,
	src_count: int,
	has_file: bool,
	has_lines: bool,
	has_snip: bool,
	pf_flags: list[str],
) -> str:
	"""Map verdict + evidence strength to confidence level."""
	if verdict == "CERTIFIED":
		if escore >= 4:
			return "high"
		if escore >= 3:
			return "high"
		return "high"  # CERTIFIED always high

	if verdict == "PLAUSIBLE":
		if escore >= 3 and src_count >= 2:
			return "medium"
		if has_file and has_snip:
			return "medium"
		if src_count >= 2:
			return "medium"
		return "low"

	if verdict == "SPECULATIVE":
		return "low"

	# REJECTED
	return "low"


def _build_reason(
	*,
	cf: dict[str, Any],
	ev: dict[str, Any],
	escore: int,
	src_count: int,
	verdict: str,
	pf_flags: list[str],
	contra_notes: list[str],
) -> list[str]:
	"""Build 2-5 bullet points explaining the verdict."""
	bullets = []

	# Evidence strength bullet
	if escore >= 4:
		bullets.append(
			f"Evidence score {escore}/5: file path, symbol, line range, "
			f"snippet, and/or log all present."
		)
	elif escore >= 2:
		present = []
		if has_concrete_file(ev):
			present.append("file")
		if has_symbols(ev):
			present.append("symbol")
		if has_line_ranges(ev):
			present.append("line range")
		if has_snippets(ev):
			present.append("snippet")
		if has_logs(ev):
			present.append("log")
		bullets.append(
			f"Evidence score {escore}/5: present={', '.join(present)}."
		)
	elif escore == 1:
		bullets.append(
			f"Evidence score {escore}/5: only one evidence type present -- weak."
		)
	else:
		bullets.append(
			"Evidence score 0/5: no concrete file, symbol, line range, "
			"snippet, or log provided."
		)

	# Source agreement bullet
	if src_count >= 3:
		bullets.append(
			f"All 3 audit sources ({', '.join(cf['agreement']['sources'])}) "
			"independently flagged this issue."
		)
	elif src_count == 2:
		bullets.append(
			f"2 of 3 sources ({', '.join(cf['agreement']['sources'])}) agree; "
			"partial independent confirmation."
		)
	else:
		bullets.append(
			f"Single-source finding (source {cf['agreement']['sources'][0]}); "
			"no independent confirmation."
		)

	# Plausibility flags
	if pf_flags:
		# Include up to 2 flags
		for flag in pf_flags[:2]:
			bullets.append(f"FP-risk: {flag}")

	# Contradiction notes
	if contra_notes:
		for note in contra_notes[:2]:
			bullets.append(note)

	# Cap at 5 bullets
	return bullets[:5]


def _build_next_artifacts(
	ev: dict[str, Any],
	cf: dict[str, Any],
	whats_missing: list[str],
) -> list[str]:
	"""What exact artifacts are needed to move toward CERTIFIED."""
	artifacts = []
	pf = primary_file_from_ev(ev)
	ps = primary_symbol_from_ev(ev)

	if not has_concrete_file(ev):
		artifacts.append(
			"Identify the exact source file (e.g., net/tquic/...) "
			"where the bug manifests."
		)
	elif not has_line_ranges(ev):
		artifacts.append(
			f"Pin down exact line range in {pf} where the fault occurs."
		)

	if not has_snippets(ev):
		artifacts.append(
			"Provide a minimal code snippet from the source showing "
			"the vulnerable pattern."
		)
	elif snippet_is_comment_only(ev):
		artifacts.append(
			"Replace comment-only snippet with actual C code from the "
			"vulnerable function."
		)

	if cf["agreement"]["count"] < 2:
		artifacts.append(
			"Obtain independent confirmation from a second auditor or "
			"a failing test case."
		)

	if not has_logs(ev):
		artifacts.append(
			"Produce a kernel log / KASAN/lockdep report or stack trace "
			"demonstrating the issue."
		)

	# Failing test
	artifacts.append(
		"Create a targeted KUnit or kselftest that triggers the bug "
		"and fails before the fix."
	)

	# Dedupe and cap
	seen = set()
	deduped = []
	for a in artifacts:
		if a not in seen:
			seen.add(a)
			deduped.append(a)
	return deduped[:5]


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def to_json_record(jf: JudgedFinding) -> dict[str, Any]:
	"""Convert JudgedFinding to a JSON-serializable dict."""
	return {
		"cid": jf.cid,
		"title": jf.title,
		"category": jf.category,
		"severity": jf.severity,
		"original_confidence": jf.original_confidence,
		"priority_score": jf.priority_score,
		"source_count": jf.source_count,
		"sources": jf.sources,
		"verdict": jf.verdict,
		"confidence_after_judging": jf.confidence_after_judging,
		"reason": jf.reason,
		"key_evidence_present": jf.key_evidence_present,
		"whats_missing": jf.whats_missing,
		"minimal_verification": jf.minimal_verification,
		"safest_fix": jf.safest_fix,
		"required_next_artifacts": jf.required_next_artifacts,
	}


def escape_md_cell(text: str) -> str:
	"""Escape pipe chars for Markdown table cells and truncate."""
	return text.replace("|", "\\|").replace("\n", " ")[:120]


def format_markdown(judged: list[JudgedFinding], total_input: int) -> str:
	"""Produce the full Markdown judging report."""
	lines = []
	lines.append("# Judged Findings Report -- Skeptical Code Audit Judge")
	lines.append("")
	lines.append("## Methodology")
	lines.append("")
	lines.append(
		"Each ConsolidatedFinding from the Master Bug Ledger was subjected to "
		"five adversarial checks: **evidence**, **plausibility**, "
		"**contradiction**, **verification plan**, and **fix safety**. "
		"Verdicts are assigned conservatively -- a finding must earn its status "
		"through concrete evidence, not volume of reports."
	)
	lines.append("")

	# --- Verdict distribution ---
	verdict_counts: dict[str, int] = {}
	conf_counts: dict[str, int] = {}
	for jf in judged:
		verdict_counts[jf.verdict] = verdict_counts.get(jf.verdict, 0) + 1
		conf_counts[jf.confidence_after_judging] = conf_counts.get(
			jf.confidence_after_judging, 0
		) + 1

	lines.append("## Summary Statistics")
	lines.append("")
	lines.append(f"- Input findings judged: **{total_input}**")
	lines.append(f"- CERTIFIED: **{verdict_counts.get('CERTIFIED', 0)}**")
	lines.append(f"- PLAUSIBLE: **{verdict_counts.get('PLAUSIBLE', 0)}**")
	lines.append(f"- SPECULATIVE: **{verdict_counts.get('SPECULATIVE', 0)}**")
	lines.append(f"- REJECTED: **{verdict_counts.get('REJECTED', 0)}**")
	lines.append("")
	lines.append("Post-judging confidence distribution:")
	lines.append(f"- high: **{conf_counts.get('high', 0)}**")
	lines.append(f"- medium: **{conf_counts.get('medium', 0)}**")
	lines.append(f"- low: **{conf_counts.get('low', 0)}**")
	lines.append("")

	# --- Main table (sorted by priority_score desc) ---
	lines.append("## Verdict Table (sorted by priority_score descending)")
	lines.append("")
	lines.append(
		"| cid | verdict | conf_after | severity | priority | "
		"key evidence? | what's missing | minimal verification | safest fix |"
	)
	lines.append(
		"|---|---|---|---|---:|---|---|---|---|"
	)

	for jf in judged:
		missing_short = "; ".join(jf.whats_missing[:2])
		if len(jf.whats_missing) > 2:
			missing_short += f" (+{len(jf.whats_missing)-2} more)"
		verify_short = "; ".join(jf.minimal_verification[:2])
		if len(jf.minimal_verification) > 2:
			verify_short += f" (+{len(jf.minimal_verification)-2} more)"

		lines.append(
			f"| {jf.cid} "
			f"| {jf.verdict} "
			f"| {jf.confidence_after_judging} "
			f"| {jf.severity} "
			f"| {jf.priority_score:.2f} "
			f"| {escape_md_cell(jf.key_evidence_present)} "
			f"| {escape_md_cell(missing_short)} "
			f"| {escape_md_cell(verify_short)} "
			f"| {escape_md_cell(jf.safest_fix)} |"
		)

	lines.append("")

	# --- Per-verdict sections with detail ---
	for verdict_label in ("CERTIFIED", "PLAUSIBLE", "SPECULATIVE", "REJECTED"):
		subset = [jf for jf in judged if jf.verdict == verdict_label]
		if not subset:
			continue

		lines.append(f"## {verdict_label} Findings ({len(subset)})")
		lines.append("")

		for jf in subset:
			lines.append(f"### {jf.cid} -- {escape_md_cell(jf.title)}")
			lines.append("")
			lines.append(
				f"**Severity:** {jf.severity} | "
				f"**Category:** {jf.category} | "
				f"**Sources:** {','.join(jf.sources)} | "
				f"**Priority:** {jf.priority_score:.2f}"
			)
			lines.append("")
			lines.append(f"**Verdict:** {jf.verdict} | "
						f"**Confidence after judging:** {jf.confidence_after_judging}")
			lines.append("")
			lines.append("**Reason:**")
			for bullet in jf.reason:
				lines.append(f"- {bullet}")
			lines.append("")
			lines.append(f"**Key evidence present:** {jf.key_evidence_present}")
			lines.append("")
			lines.append("**What's missing:**")
			for item in jf.whats_missing:
				lines.append(f"- {item}")
			lines.append("")
			lines.append("**Minimal verification:**")
			for cmd in jf.minimal_verification:
				lines.append(f"- `{cmd}`")
			lines.append("")
			lines.append(f"**Safest fix:** {jf.safest_fix}")
			lines.append("")
			lines.append("**Required next artifacts:**")
			for art in jf.required_next_artifacts:
				lines.append(f"- {art}")
			lines.append("")

	# --- Rules reminder ---
	lines.append("---")
	lines.append("")
	lines.append("*Generated by judge_findings.py -- Skeptical Code Audit Judge.*")
	lines.append("*No new findings introduced. No commands were executed.*")
	lines.append("")

	return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Skeptical Code Audit Judge for consolidated findings."
	)
	parser.add_argument(
		"--input-json",
		default="/workspace/llm findings/MASTER_BUG_LEDGER.json",
		help="Path to MASTER_BUG_LEDGER.json",
	)
	parser.add_argument(
		"--input-md",
		default="/workspace/llm findings/MASTER_BUG_LEDGER.md",
		help="Path to MASTER_BUG_LEDGER.md (used for context/validation)",
	)
	parser.add_argument(
		"--out-json",
		default="/workspace/llm findings/JUDGED_FINDINGS.json",
		help="Output judged JSON path",
	)
	parser.add_argument(
		"--out-md",
		default="/workspace/llm findings/JUDGED_FINDINGS.md",
		help="Output judged Markdown path",
	)
	return parser.parse_args()


def main() -> None:
	args = parse_args()

	# Load consolidated findings
	input_path = Path(args.input_json)
	if not input_path.exists():
		print(f"ERROR: {input_path} not found")
		return

	consolidated = json.loads(input_path.read_text(encoding="utf-8"))
	if not isinstance(consolidated, list):
		print("ERROR: Expected a JSON array of ConsolidatedFinding objects")
		return

	print(f"Loaded {len(consolidated)} consolidated findings from {input_path}")

	# Validate MD exists (informational)
	md_path = Path(args.input_md)
	if md_path.exists():
		md_text = md_path.read_text(encoding="utf-8")
		# Count findings mentioned in the MD summary table
		md_cid_count = md_text.count("| CF-")
		print(f"Master MD references ~{md_cid_count} CID entries (cross-check)")
	else:
		print(f"WARNING: {md_path} not found -- proceeding with JSON only")

	# Judge each finding
	judged: list[JudgedFinding] = []
	for cf in consolidated:
		jf = judge_finding(cf)
		judged.append(jf)

	# Sort by priority_score descending (same as input), then by verdict quality
	judged.sort(
		key=lambda jf: (
			-jf.priority_score,
			VERDICT_ORDER.get(jf.verdict, 99),
			SEV_ORDER.get(jf.severity, 99),
			jf.cid,
		)
	)

	# Print summary
	verdict_counts: dict[str, int] = {}
	conf_counts: dict[str, int] = {}
	for jf in judged:
		verdict_counts[jf.verdict] = verdict_counts.get(jf.verdict, 0) + 1
		conf_counts[jf.confidence_after_judging] = conf_counts.get(
			jf.confidence_after_judging, 0
		) + 1

	print(f"\nJudging complete. Results:")
	print(f"  CERTIFIED:   {verdict_counts.get('CERTIFIED', 0)}")
	print(f"  PLAUSIBLE:   {verdict_counts.get('PLAUSIBLE', 0)}")
	print(f"  SPECULATIVE: {verdict_counts.get('SPECULATIVE', 0)}")
	print(f"  REJECTED:    {verdict_counts.get('REJECTED', 0)}")
	print(f"\nPost-judging confidence:")
	print(f"  high:   {conf_counts.get('high', 0)}")
	print(f"  medium: {conf_counts.get('medium', 0)}")
	print(f"  low:    {conf_counts.get('low', 0)}")

	# Write JSON output
	json_records = [to_json_record(jf) for jf in judged]
	out_json = Path(args.out_json)
	out_json.write_text(
		json.dumps(json_records, indent=2, ensure_ascii=False),
		encoding="utf-8",
	)
	print(f"\nJSON output: {out_json}")

	# Write Markdown output
	md_output = format_markdown(judged, len(consolidated))
	out_md = Path(args.out_md)
	out_md.write_text(md_output, encoding="utf-8")
	print(f"Markdown output: {out_md}")


if __name__ == "__main__":
	main()
