"""One finding in, one run record out."""

import hashlib
import time

from .prompt import build_baseline_prompt, build_prompt
from .validate import validate


def assist(finding: str, retriever, generator, mode: str = "hybrid",
           k: int = 5, alpha: float = 0.7, pool: int = 20, code: str = "") -> dict:
    """Retrieve, prompt, generate, validate. retriever=None gives the
    ungrounded baseline: same generator, same output format, no evidence."""
    if retriever is None:
        hits, prompt = [], build_baseline_prompt(finding, code)
    else:
        hits = retriever.search(finding, mode, k=k, alpha=alpha, pool=pool)
        prompt = build_prompt(finding, hits, code=code)
    reply = generator.generate(prompt)
    return {
        "finding": finding,
        "code": code,
        "evidence": [{"label": f"E{i}", "chunk_id": h.chunk_id, "source": h.source,
                      "text": h.text}
                     for i, h in enumerate(hits, 1)],
        "prompt_sha1": hashlib.sha1(prompt.encode()).hexdigest()[:12],
        "output": reply["text"],
        "seconds": reply["seconds"],
        "tokens": reply.get("tokens"),
        "validation": validate(reply["text"], len(hits), grounded=retriever is not None),
        "generator": generator.config() if hasattr(generator, "config") else {},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
