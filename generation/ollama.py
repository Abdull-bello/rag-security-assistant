"""Minimal client for a local Ollama server (standard library only)."""

import json
import time
import urllib.request

DEFAULT_URL = "http://localhost:11434/api/generate"


class OllamaGenerator:
    def __init__(self, model: str, seed: int = 42, temperature: float = 0.0,
                 num_ctx: int = 4096, num_predict: int = 400,
                 url: str = DEFAULT_URL, timeout: int = 900):
        self.model, self.url, self.timeout = model, url, timeout
        self.options = {"seed": seed, "temperature": temperature,
                        "num_ctx": num_ctx, "num_predict": num_predict}

    def config(self) -> dict:
        return {"model": self.model, **self.options}

    def generate(self, prompt: str) -> dict:
        body = json.dumps({"model": self.model, "prompt": prompt,
                           "stream": False, "options": self.options}).encode()
        request = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"})
        start = time.time()
        with urllib.request.urlopen(request, timeout=self.timeout) as reply:
            data = json.load(reply)
        return {"text": data.get("response", ""),
                "seconds": round(time.time() - start, 2),
                "tokens": data.get("eval_count")}
