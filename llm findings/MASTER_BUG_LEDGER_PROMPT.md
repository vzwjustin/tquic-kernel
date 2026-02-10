ROLE: Consolidator. You merge 3 independent audit reports into one Master
Bug Ledger.

INPUTS:
- REPORT_A_JSON (Codex normalized): `llm findings/codex.json`
- REPORT_B_JSON (Claude/Opus normalized): `llm findings/claude.json`
- REPORT_C_JSON (Gemini normalized): `llm findings/gemini_findings.json`

TASK:
1) Parse all FindingCards.
2) Deduplicate by clustering items that refer to the same underlying issue.
   Use a "fingerprint" heuristic:
   fingerprint = normalized(title keywords) + primary file_path +
   primary symbol + category
3) For each cluster, create one ConsolidatedFinding with:
   - merged evidence (union of paths/symbols/lines/snippets)
   - reconciled severity (take highest if evidence supports; otherwise keep
     highest-but-flagged)
   - reconciled confidence:
        high only if >=2 reports agree OR one report provides strong evidence
        (specific file+line+snippet/log)
        medium if plausible but evidence incomplete
        low if speculative/hand-wavy
   - conflicts: capture direct contradictions between reports
4) Output:
   A) A prioritized list (highest priority first) with a priority_score:
      priority_score = impact_weight * likelihood_weight
      impact_weight: S0=10, S1=7, S2=4, S3=1
      likelihood_weight: high=1.0, medium=0.7, low=0.4
   B) A "Missing Evidence" checklist (what info is needed to confirm each)
   C) A "Fix Plan" that orders fixes to minimize risk and unblocks follow-on
      issues.

OUTPUT FORMAT:
- First: Markdown report (human-readable)
- Then: A JSON array of ConsolidatedFinding objects (machine-usable)

ConsolidatedFinding schema:
{
  "cid": "CF-001",
  "fingerprint": "string",
  "title": "string",
  "category": "...",
  "severity": "S0|S1|S2|S3",
  "confidence": "high|medium|low",
  "priority_score": number,
  "summary": "2-4 lines",
  "merged_evidence": { ...same shape as FindingCard.evidence... },
  "agreement": { "count": 1-3, "sources": ["A","B","C"] },
  "conflicts": ["list contradictions or uncertainty"],
  "verification_commands": [
    "ripgrep commands, unit test commands, minimal repro commands"
  ],
  "recommended_fix": "best merged fix approach",
  "tests_to_add": ["..."],
  "risk_notes": "what could go wrong fixing this"
}

REPORT_A_JSON:
<<<PASTE CONTENTS OF llm findings/codex.json>>>

REPORT_B_JSON:
<<<PASTE CONTENTS OF llm findings/claude.json>>>

REPORT_C_JSON:
<<<PASTE CONTENTS OF llm findings/gemini_findings.json>>>
