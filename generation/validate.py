"""Check the model output against the evidence it was given."""

import re

VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"}
CITE = re.compile(r"\[(E\d+)\]")
NO_SUPPORT = re.compile(r"no passage supports", re.I)


def parse_verdict(text: str):
    m = re.search(r"VERDICT:\s*([A-Za-z_ ]+)", text)
    if not m:
        return None
    word = m.group(1).strip().upper().replace(" ", "_")
    for v in VERDICTS:
        if word.startswith(v):
            return v
    return None


def claim_lines(text: str):
    """The severity claim and each numbered remediation step.

    Small models often put the severity reason on the line after SEVERITY, so
    the severity claim runs from that line to the next blank line or to
    REMEDIATION. A numbered step likewise includes its continuation lines."""
    claims, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        upper = line.upper()
        if upper.startswith("SEVERITY:") or re.match(r"^\d+[.)]\s", line):
            if current is not None:
                claims.append(current)
            current = line
        elif not line or upper.startswith("REMEDIATION") or upper.startswith("VERDICT:"):
            if current is not None:
                claims.append(current)
            current = None
        elif current is not None:
            current += " " + line
    if current is not None:
        claims.append(current)
    return claims


def empty_claim(line: str) -> bool:
    """A claim with no content of its own: only labels, or the answer
    template copied unfilled (for example "1. <first step> [E1]")."""
    t = re.sub(r"^(SEVERITY:|\d+[.)])", "", line.strip(), flags=re.I)
    t = CITE.sub("", t)
    t = re.sub(r"<[^>]*>", "", t)
    return len(re.sub(r"[\s,.:;\[\]E\d]", "", t)) == 0


def validate(text: str, n_evidence: int, grounded: bool = True) -> dict:
    """Citation checks. Counts use the labels E1..E{n_evidence}."""
    allowed = {f"E{i}" for i in range(1, n_evidence + 1)}
    claims = claim_lines(text)
    cited_claims = invalid = total_cites = 0
    for line in claims:
        cites = CITE.findall(line)
        total_cites += len(cites)
        bad = [c for c in cites if c not in allowed]
        invalid += len(bad)
        if empty_claim(line):
            continue
        if (cites and not bad) or NO_SUPPORT.search(line):
            cited_claims += 1
    verdict = parse_verdict(text)
    result = {"verdict": verdict, "format_ok": verdict is not None and len(claims) >= 2,
              "n_claims": len(claims)}
    if grounded:
        result.update({
            "n_citations": total_cites,
            "n_invalid_citations": invalid,
            "claims_cited": cited_claims,
            "citation_coverage": round(cited_claims / len(claims), 4) if claims else 0.0,
            "all_citations_valid": invalid == 0 and total_cites > 0
                                   and not any(empty_claim(l) for l in claims),
            "empty_claims": sum(empty_claim(l) for l in claims),
        })
    return result
