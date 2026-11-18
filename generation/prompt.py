"""The fixed instruction and the prompt builder.

Evidence is shown to the model under short labels E1 to E5. The model cites
the label; the validator maps each label back to a stored chunk identifier.
Short labels are easier for a small model to copy exactly than a long
identifier such as cwe-struct-89-mitigations.
"""

RULES = """You are a security assistant helping an analyst judge a scanner finding.
Use only the numbered evidence passages below. Do not use outside knowledge.
Judge the verdict from the code shown with the finding, if code is shown.
Every remediation step and the severity reason must end with the label of the
passage that supports it, in square brackets, for example [E2]. A step with no
label is not accepted. If no passage supports a step, end it with the words
"No passage supports this" instead of a label.

Answer in exactly this format and nothing else:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE or UNCERTAIN
SEVERITY: <Low, Medium, High or Critical>. <one sentence of reason> [E#]
REMEDIATION:
1. <first step> [E#]
2. <second step> [E#]
3. <third step> [E#]
(three to five steps, each ending with a label)
"""

BASELINE_RULES = """You are a security assistant helping an analyst judge a scanner finding.
Judge the verdict from the code shown with the finding, if code is shown.

Answer in exactly this format and nothing else:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE or UNCERTAIN
SEVERITY: <Low, Medium, High or Critical>. <one sentence of reason>
REMEDIATION:
1. <first step>
2. <second step>
3. <third step>
(three to five steps)
"""


def label(i: int) -> str:
    return f"E{i}"


def finding_block(finding: str, code: str = "") -> str:
    """The finding, with the flagged source lines when they are available.
    The code is given to the generator only. Retrieval uses the finding text."""
    if not code.strip():
        return f"FINDING:\n{finding}\n"
    return (f"FINDING:\n{finding}\n\nCODE AROUND THE FINDING "
            f"(the flagged line starts with >>):\n{code}\n")


def build_prompt(finding: str, hits, max_chars: int = 1800, code: str = "") -> str:
    """Grounded prompt. `hits` is the ranked list from the retriever."""
    blocks = []
    for i, hit in enumerate(hits, 1):
        text = hit.text if len(hit.text) <= max_chars else hit.text[:max_chars] + " ..."
        blocks.append(f"[{label(i)}] ({hit.source}) {text}")
    evidence = "\n\n".join(blocks) if blocks else "(no passages retrieved)"
    return f"{RULES}\nEVIDENCE:\n{evidence}\n\n{finding_block(finding, code)}"


def build_baseline_prompt(finding: str, code: str = "") -> str:
    return f"{BASELINE_RULES}\n{finding_block(finding, code)}"
