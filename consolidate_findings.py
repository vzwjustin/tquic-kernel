#!/usr/bin/env python3
"""
Consolidate Codex/Claude/Gemini FindingCards into a Master Bug Ledger.

Outputs:
  - Markdown report
  - JSON array of ConsolidatedFinding objects
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SEV_ORDER = {"S0": 0, "S1": 1, "S2": 2, "S3": 3}
SEV_IMPACT = {"S0": 10, "S1": 7, "S2": 4, "S3": 1}
CONF_LIKELIHOOD = {"high": 1.0, "medium": 0.7, "low": 0.4}
GENERIC_FIX_TEXT = "See original report for recommendation"

STOPWORDS = {
	"a",
	"an",
	"and",
	"are",
	"as",
	"at",
	"be",
	"by",
	"for",
	"from",
	"in",
	"is",
	"it",
	"its",
	"of",
	"on",
	"or",
	"that",
	"the",
	"to",
	"uses",
	"using",
	"with",
	"without",
	"does",
	"not",
	"into",
	"during",
	"after",
	"before",
	"always",
	"only",
	"via",
	"over",
	"under",
	"may",
	"can",
	"could",
	"should",
	"will",
}

GENERIC_SYMBOLS = {
	"and",
	"bits",
	"data",
	"defect",
	"issues",
	"object",
	"tables",
	"void",
	"space",
	"sockets",
}


@dataclass
class Finding:
	source: str
	id: str
	title: str
	category: str
	severity: str
	confidence: str
	impact: str
	evidence: dict[str, Any]
	repro: dict[str, Any]
	root_cause_hypothesis: str
	fix_suggestion: str
	tests_to_add: list[str]
	notes: str
	title_tokens: list[str] = field(default_factory=list)
	primary_file: str = ""
	primary_symbol: str = ""
	fingerprint: str = ""


def load_findings(path: Path, source_letter: str) -> list[Finding]:
	raw = json.loads(path.read_text(encoding="utf-8"))
	if isinstance(raw, dict):
		items = raw.get("findings", [])
	elif isinstance(raw, list):
		items = raw
	else:
		items = []

	out: list[Finding] = []
	for i, item in enumerate(items):
		if not isinstance(item, dict):
			continue
		evidence = item.get("evidence") or {}
		out.append(
			Finding(
				source=source_letter,
				id=str(item.get("id", f"{source_letter}-{i+1}")),
				title=str(item.get("title", "")).strip() or f"Untitled finding {i+1}",
				category=normalize_category(str(item.get("category", "correctness"))),
				severity=normalize_severity(str(item.get("severity", "S2"))),
				confidence=normalize_confidence(str(item.get("confidence", "medium"))),
				impact=str(item.get("impact", "")).strip(),
				evidence=normalize_evidence(evidence),
				repro=item.get("repro") if isinstance(item.get("repro"), dict) else {},
				root_cause_hypothesis=str(item.get("root_cause_hypothesis", "")).strip(),
				fix_suggestion=str(item.get("fix_suggestion", "")).strip(),
				tests_to_add=[
					str(t).strip()
					for t in item.get("tests_to_add", [])
					if isinstance(t, str) and str(t).strip()
				],
				notes=str(item.get("notes", "")).strip(),
			)
		)
	return out


def normalize_severity(sev: str) -> str:
	sev = sev.strip().upper()
	if sev in SEV_ORDER:
		return sev
	return "S2"


def normalize_confidence(conf: str) -> str:
	c = conf.strip().lower()
	if c in {"high", "medium", "low"}:
		return c
	return "medium"


def normalize_category(cat: str) -> str:
	c = cat.strip().lower()
	return c or "correctness"


def normalize_path(path: str) -> str:
	p = path.strip().replace("\\", "/")
	if not p:
		return ""
	match = re.search(r"(net/(?:tquic|quic)/.*)", p)
	if match:
		return match.group(1)
	return p.lstrip("./")


def normalize_symbol(symbol: str) -> str:
	s = re.sub(r"[^A-Za-z0-9_]", "", symbol.strip().lower())
	if not s:
		return ""
	if s in GENERIC_SYMBOLS:
		return ""
	if len(s) < 3:
		return ""
	return s


def normalize_evidence(evidence: dict[str, Any]) -> dict[str, list[str]]:
	paths = []
	for p in evidence.get("file_paths", []) or []:
		if isinstance(p, str):
			np = normalize_path(p)
			if np:
				paths.append(np)

	symbols = []
	for s in evidence.get("symbols", []) or []:
		if isinstance(s, str):
			ns = normalize_symbol(s)
			if ns:
				symbols.append(ns)

	line_ranges = []
	for lr in evidence.get("line_ranges", []) or []:
		if isinstance(lr, str):
			line_ranges.append(normalize_line_range(lr))

	snippets = [s for s in (evidence.get("snippets", []) or []) if isinstance(s, str) and s.strip()]
	logs = [l for l in (evidence.get("logs_or_errors", []) or []) if isinstance(l, str) and l.strip()]

	return {
		"file_paths": dedupe_list(paths),
		"symbols": dedupe_list(symbols),
		"line_ranges": dedupe_list(line_ranges),
		"snippets": dedupe_list(snippets),
		"logs_or_errors": dedupe_list(logs),
	}


def normalize_line_range(line_range: str) -> str:
	lr = line_range.strip().replace("\\", "/")
	if not lr:
		return lr
	match = re.match(r"(.+?):(\d+)-(\d+)$", lr)
	if not match:
		return lr
	path, start, end = match.groups()
	return f"{normalize_path(path)}:{start}-{end}"


def stem_token(token: str) -> str:
	t = token.lower()
	if t in {"uaf", "useafterfree", "use_after_free"}:
		return "useafterfree"
	if t in {"oob", "outofbounds", "out_of_bounds"}:
		return "outofbounds"
	for suffix in ("ing", "ed", "es", "s"):
		if len(t) > 4 and t.endswith(suffix):
			t = t[: -len(suffix)]
			break
	return t


def title_keywords(title: str) -> list[str]:
	tokens = re.findall(r"[A-Za-z0-9_]+", title.lower())
	out = []
	for tok in tokens:
		if tok in STOPWORDS:
			continue
		if len(tok) < 3:
			continue
		st = stem_token(tok)
		if st and st not in STOPWORDS:
			out.append(st)
	return dedupe_list(out)[:8]


def primary_file(evidence: dict[str, list[str]]) -> str:
	if evidence["file_paths"]:
		return evidence["file_paths"][0]
	if evidence["line_ranges"]:
		lr = evidence["line_ranges"][0]
		if ":" in lr:
			return lr.split(":", 1)[0]
	return "unknown_file"


def primary_symbol(evidence: dict[str, list[str]]) -> str:
	for s in evidence["symbols"]:
		if "_" in s or s.startswith("tquic") or len(s) > 5:
			return s
	if evidence["symbols"]:
		return evidence["symbols"][0]
	return "unknown_symbol"


def build_fingerprint(finding: Finding) -> str:
	keywords = "-".join(sorted(finding.title_tokens)[:6]) or "untitled"
	return f"{keywords}|{finding.primary_file}|{finding.primary_symbol}|{finding.category}"


def jaccard(a: set[str], b: set[str]) -> float:
	if not a and not b:
		return 1.0
	if not a or not b:
		return 0.0
	return len(a & b) / len(a | b)


def has_strong_evidence(finding: Finding) -> bool:
	ev = finding.evidence
	has_path = bool(ev["file_paths"])
	has_precise = bool(ev["line_ranges"] or ev["snippets"] or ev["logs_or_errors"])
	return has_path and has_precise


def has_any_evidence(finding: Finding) -> bool:
	ev = finding.evidence
	return any(bool(ev[k]) for k in ("file_paths", "symbols", "line_ranges", "snippets", "logs_or_errors"))


def dedupe_list(items: list[str]) -> list[str]:
	seen = set()
	out = []
	for item in items:
		if item in seen:
			continue
		seen.add(item)
		out.append(item)
	return out


def cluster_findings(findings: list[Finding]) -> list[list[Finding]]:
	clusters: dict[str, list[Finding]] = {}
	secondary: dict[str, list[str]] = defaultdict(list)
	rep_tokens: dict[str, set[str]] = {}

	for f in findings:
		f.title_tokens = title_keywords(f.title)
		f.primary_file = primary_file(f.evidence)
		f.primary_symbol = primary_symbol(f.evidence)
		f.fingerprint = build_fingerprint(f)

		if f.fingerprint in clusters:
			clusters[f.fingerprint].append(f)
			rep_tokens[f.fingerprint].update(f.title_tokens)
			continue

		secondary_key = f"{f.primary_file}|{f.primary_symbol}|{f.category}"
		matched_fp = ""
		best_score = 0.0
		for cand_fp in secondary.get(secondary_key, []):
			score = jaccard(set(f.title_tokens), rep_tokens[cand_fp])
			if score > best_score:
				best_score = score
				matched_fp = cand_fp

		# Keep fingerprint as primary heuristic; allow title-variant merge.
		if matched_fp and best_score >= 0.45:
			clusters[matched_fp].append(f)
			rep_tokens[matched_fp].update(f.title_tokens)
		else:
			clusters[f.fingerprint] = [f]
			secondary[secondary_key].append(f.fingerprint)
			rep_tokens[f.fingerprint] = set(f.title_tokens)

	return list(clusters.values())


def best_title(cluster: list[Finding]) -> str:
	def score(f: Finding) -> tuple[int, int, int]:
		sev_score = -SEV_ORDER[f.severity]  # S0 first
		strength = 1 if has_strong_evidence(f) else 0
		length = len(f.title)
		return (sev_score, strength, -length)

	return sorted(cluster, key=score, reverse=True)[0].title


def reconcile_severity(cluster: list[Finding]) -> tuple[str, list[str]]:
	conflicts = []
	highest = sorted(cluster, key=lambda f: SEV_ORDER[f.severity])[0].severity
	highest_items = [f for f in cluster if f.severity == highest]
	if any(has_strong_evidence(f) for f in highest_items):
		return highest, conflicts

	conflicts.append(
		f"Highest severity {highest} retained but weakly evidenced in this cluster."
	)
	return highest, conflicts


def reconcile_confidence(cluster: list[Finding]) -> str:
	sources = {f.source for f in cluster}
	if len(sources) >= 2:
		return "high"
	if any(has_strong_evidence(f) for f in cluster):
		return "high"
	if any(has_any_evidence(f) for f in cluster):
		return "medium"
	return "low"


def merge_evidence(cluster: list[Finding]) -> dict[str, list[str]]:
	keys = ("file_paths", "symbols", "line_ranges", "snippets", "logs_or_errors")
	merged = {k: [] for k in keys}
	for f in cluster:
		for k in keys:
			merged[k].extend(f.evidence.get(k, []))
	for k in keys:
		merged[k] = dedupe_list(merged[k])
	return merged


def category_vote(cluster: list[Finding]) -> str:
	c = Counter(f.category for f in cluster)
	return c.most_common(1)[0][0]


def cluster_conflicts(cluster: list[Finding], prior_conflicts: list[str]) -> list[str]:
	conflicts = list(prior_conflicts)
	categories = sorted({f.category for f in cluster})
	severities = sorted({f.severity for f in cluster}, key=lambda s: SEV_ORDER[s])

	if len(categories) > 1:
		conflicts.append(f"Category disagreement across reports: {', '.join(categories)}.")
	if len(severities) > 1:
		conflicts.append(f"Severity disagreement across reports: {', '.join(severities)}.")
	if len({f.source for f in cluster}) == 1:
		conflicts.append("Single-source finding; independent confirmation still needed.")

	return dedupe_list(conflicts)


def merged_fix(cluster: list[Finding], title: str, category: str) -> str:
	fixes = [
		f.fix_suggestion.strip()
		for f in cluster
		if f.fix_suggestion.strip()
		and GENERIC_FIX_TEXT.lower() not in f.fix_suggestion.strip().lower()
	]
	fixes = dedupe_list(fixes)
	if fixes:
		if len(fixes) == 1:
			return fixes[0]
		return " / ".join(fixes[:3])

	if category in {"memory", "security"}:
		return (
			"Add strict validation and bounds checks at parse boundaries, enforce "
			"lifetime/ownership rules, and fail closed on malformed input."
		)
	if category == "concurrency":
		return (
			"Establish one synchronization model for this code path and make all "
			"state transitions/lookup paths follow it consistently."
		)
	return (
		f"Implement an RFC-compliant correction for '{title}', then add targeted "
		"regression coverage to prevent reintroduction."
	)


def merged_tests(cluster: list[Finding], title: str, primary_path: str) -> list[str]:
	tests = []
	for f in cluster:
		tests.extend(f.tests_to_add)
	tests = dedupe_list([t for t in tests if t and t != "…"])
	if tests:
		return tests[:6]

	base = f"Add regression test for: {title}"
	if primary_path != "unknown_file":
		base += f" ({primary_path})"
	return [
		base,
		"Add malformed-input negative test that validates graceful error handling.",
	]


def risk_notes(cluster: list[Finding], category: str, primary_path: str) -> str:
	if category in {"memory", "security"}:
		return (
			"Fixes in parser/crypto/lifetime code may alter packet acceptance logic. "
			"Watch for interoperability regressions and accidental behavior changes "
			"in fast-path RX handling."
		)
	if category == "concurrency":
		return (
			"Locking/ordering changes can cause deadlocks or throughput regressions "
			"if not validated under stress and teardown races."
		)
	return (
		"Protocol correctness fixes can shift timing/state-machine behavior; "
		"verify against interop traces and existing retransmission/loss logic."
	)


def verification_commands(
	title: str,
	primary_path: str,
	primary_symbol_name: str,
	first_keyword: str,
) -> list[str]:
	cmds = []
	if primary_path != "unknown_file":
		cmds.append(f"rg -n \"{re.escape(primary_symbol_name)}\" \"{primary_path}\"")
		if first_keyword:
			cmds.append(f"rg -n \"{re.escape(first_keyword)}\" \"{primary_path}\"")
	cmds.append("make M=net/tquic W=1")
	cmds.append("make M=net/tquic C=1")
	return dedupe_list(cmds)[:5]


def missing_evidence_items(cf: dict[str, Any]) -> list[str]:
	missing = []
	ev = cf["merged_evidence"]
	if not ev["file_paths"]:
		missing.append("Pinpoint at least one concrete source file path.")
	if not ev["line_ranges"]:
		missing.append("Capture exact line range(s) where the fault manifests.")
	if not ev["snippets"]:
		missing.append("Include a minimal code snippet proving the issue.")
	if cf["agreement"]["count"] < 2:
		missing.append("Get independent confirmation from a second report/source.")

	# Repro data only exists at raw finding level; ask for repro if confidence < high.
	if cf["confidence"] != "high":
		missing.append("Add minimal repro steps with expected vs actual behavior.")

	return missing or ["No major evidence gaps detected."]


def format_markdown(
	consolidated: list[dict[str, Any]],
	missing_map: dict[str, list[str]],
	input_counts: dict[str, int],
) -> str:
	lines = []
	lines.append("# Master Bug Ledger (Consolidated)")
	lines.append("")
	lines.append("## Inputs")
	lines.append(
		f"- REPORT_A_JSON (Codex): {input_counts['A']} FindingCards"
	)
	lines.append(
		f"- REPORT_B_JSON (Opus/Claude): {input_counts['B']} FindingCards"
	)
	lines.append(
		f"- REPORT_C_JSON (Gemini): {input_counts['C']} FindingCards"
	)
	lines.append("")
	lines.append(
		f"Total consolidated findings: **{len(consolidated)}**"
	)
	lines.append("")
	lines.append("## A) Prioritized List")
	lines.append("")
	lines.append(
		"| Rank | CID | Priority | Severity | Confidence | Sources | Title |"
	)
	lines.append(
		"|---:|---|---:|---|---|---|---|"
	)
	for idx, cf in enumerate(consolidated, 1):
		sources = ",".join(cf["agreement"]["sources"])
		title = cf["title"].replace("|", "\\|")
		lines.append(
			f"| {idx} | {cf['cid']} | {cf['priority_score']:.2f} | "
			f"{cf['severity']} | {cf['confidence']} | {sources} | {title} |"
		)
	lines.append("")
	lines.append("## B) Missing Evidence Checklist")
	lines.append("")
	for cf in consolidated:
		lines.append(f"### {cf['cid']} - {cf['title']}")
		for item in missing_map[cf["cid"]]:
			lines.append(f"- [ ] {item}")
		lines.append("")
	lines.append("## C) Fix Plan (Risk-Minimizing Order)")
	lines.append("")

	# Global plan by priority/category to unblock downstream issues.
	high_prio = [c for c in consolidated if c["priority_score"] >= 7.0]
	mem_sec = [c for c in high_prio if c["category"] in {"memory", "security"}]
	core_proto = [
		c
		for c in high_prio
		if c["category"] in {"correctness", "concurrency"}
	]
	other = [c for c in high_prio if c not in mem_sec and c not in core_proto]

	lines.append("1. **Stabilize memory-safety and security-critical parser paths first**")
	lines.append(
		f"   - Address {len(mem_sec)} S0/S1 memory+security findings to reduce crash/exploit risk before behavior tuning."
	)
	lines.append("2. **Fix protocol-state and packet processing correctness**")
	lines.append(
		f"   - Triage {len(core_proto)} high-priority correctness/concurrency findings once safety rails are in place."
	)
	lines.append("3. **Resolve residual high-priority architecture issues**")
	lines.append(
		f"   - Handle remaining {len(other)} high-priority items and remove temporary mitigations."
	)
	lines.append("4. **Backfill evidence gaps + tests before closeout**")
	lines.append(
		"   - For single-source or low-evidence clusters, require line-level proof and a regression test to close."
	)
	lines.append("")
	lines.append("## Notes")
	lines.append(
		"- Severity reconciliation keeps the highest severity; weakly evidenced cases are explicitly flagged in `conflicts`."
	)
	lines.append(
		"- Confidence is high only with multi-source agreement or strong single-source evidence."
	)
	lines.append("")
	return "\n".join(lines) + "\n"


def consolidate(findings_by_source: dict[str, list[Finding]]) -> list[dict[str, Any]]:
	all_findings = []
	for src in ("A", "B", "C"):
		all_findings.extend(findings_by_source[src])

	clusters = cluster_findings(all_findings)
	consolidated = []

	for idx, cluster in enumerate(clusters, 1):
		title = best_title(cluster)
		category = category_vote(cluster)
		severity, sev_conflicts = reconcile_severity(cluster)
		confidence = reconcile_confidence(cluster)
		priority = SEV_IMPACT[severity] * CONF_LIKELIHOOD[confidence]
		merged_ev = merge_evidence(cluster)
		sources = sorted({f.source for f in cluster})
		conflicts = cluster_conflicts(cluster, sev_conflicts)

		p_file = primary_file(merged_ev)
		p_symbol = primary_symbol(merged_ev)
		keywords = title_keywords(title)
		first_kw = keywords[0] if keywords else ""
		fp = (
			f"{'-'.join(sorted(keywords)[:6]) or 'untitled'}|"
			f"{p_file}|{p_symbol}|{category}"
		)

		summary_lines = [
			f"Consolidates {len(cluster)} report item(s) from source(s) {', '.join(sources)}.",
			f"Primary locus: {p_file} :: {p_symbol}. Category={category}, severity={severity}.",
			f"Evidence union: {len(merged_ev['file_paths'])} file(s), "
			f"{len(merged_ev['line_ranges'])} line range(s), "
			f"{len(merged_ev['snippets'])} snippet(s).",
		]

		consolidated.append(
			{
				"cid": f"CF-{idx:03d}",
				"fingerprint": fp,
				"title": title,
				"category": category,
				"severity": severity,
				"confidence": confidence,
				"priority_score": round(priority, 2),
				"summary": "\n".join(summary_lines),
				"merged_evidence": merged_ev,
				"agreement": {"count": len(sources), "sources": sources},
				"conflicts": conflicts,
				"verification_commands": verification_commands(
					title, p_file, p_symbol, first_kw
				),
				"recommended_fix": merged_fix(cluster, title, category),
				"tests_to_add": merged_tests(cluster, title, p_file),
				"risk_notes": risk_notes(cluster, category, p_file),
			}
		)

	consolidated.sort(
		key=lambda cf: (
			-cf["priority_score"],
			SEV_ORDER[cf["severity"]],
			-cf["agreement"]["count"],
			cf["title"].lower(),
		)
	)

	# Reindex CID by final priority order.
	for i, cf in enumerate(consolidated, 1):
		cf["cid"] = f"CF-{i:03d}"

	return consolidated


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Consolidate normalized findings.")
	parser.add_argument(
		"--codex",
		default="/workspace/llm findings/codex.json",
		help="Path to Codex normalized JSON",
	)
	parser.add_argument(
		"--claude",
		default="/workspace/llm findings/claude.json",
		help="Path to Claude/Opus normalized JSON",
	)
	parser.add_argument(
		"--gemini",
		default="/workspace/llm findings/gemini_findings.json",
		help="Path to Gemini normalized JSON",
	)
	parser.add_argument(
		"--out-json",
		default="/workspace/llm findings/MASTER_BUG_LEDGER.json",
		help="Output JSON path",
	)
	parser.add_argument(
		"--out-md",
		default="/workspace/llm findings/MASTER_BUG_LEDGER.md",
		help="Output Markdown path",
	)
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	findings_by_source = {
		"A": load_findings(Path(args.codex), "A"),
		"B": load_findings(Path(args.claude), "B"),
		"C": load_findings(Path(args.gemini), "C"),
	}

	consolidated = consolidate(findings_by_source)
	missing_map = {cf["cid"]: missing_evidence_items(cf) for cf in consolidated}

	md = format_markdown(
		consolidated=consolidated,
		missing_map=missing_map,
		input_counts={k: len(v) for k, v in findings_by_source.items()},
	)

	out_json = Path(args.out_json)
	out_md = Path(args.out_md)
	out_json.write_text(json.dumps(consolidated, indent=2), encoding="utf-8")
	out_md.write_text(md, encoding="utf-8")

	print("Consolidation complete")
	print(
		f"Inputs: A={len(findings_by_source['A'])}, "
		f"B={len(findings_by_source['B'])}, C={len(findings_by_source['C'])}"
	)
	print(f"Consolidated findings: {len(consolidated)}")
	print(f"Markdown: {out_md}")
	print(f"JSON: {out_json}")


if __name__ == "__main__":
	main()
