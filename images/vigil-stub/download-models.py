#!/usr/bin/env python3
"""Build-time model fetcher for the vigil scanner image.

Downloads every detection artifact with bounded retries so a flaky CDN does
not fail the docker build. Layout in /models:

    tokenizer.json            all-MiniLM-L6-v2 tokenizer (vector engine)
    model_quantized.onnx      all-MiniLM-L6-v2 int8 (23 MB)
    transformer/tokenizer.json + model.onnx
                              protectai/deberta-v3-base-prompt-injection (fp32)
    canonical/tokenizer.json + model.onnx
                              protectai/deberta-v3-base-prompt-injection-v2
"""

import os
import time
import urllib.request

FILES = [
    # (url, destination)
    ("https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/tokenizer.json",
     "/models/tokenizer.json"),
    ("https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/onnx/model_quantized.onnx",
     "/models/model_quantized.onnx"),
    ("https://huggingface.co/protectai/deberta-v3-base-prompt-injection/resolve/main/onnx/tokenizer.json",
     "/models/transformer/tokenizer.json"),
    ("https://huggingface.co/protectai/deberta-v3-base-prompt-injection/resolve/main/onnx/model.onnx",
     "/models/transformer/model.onnx"),
    ("https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/tokenizer.json",
     "/models/canonical/tokenizer.json"),
    ("https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model.onnx",
     "/models/canonical/model.onnx"),
]

RETRIES = 5


def fetch(url, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    for attempt in range(1, RETRIES + 1):
        try:
            print(f"fetching {url} -> {dest}", flush=True)
            urllib.request.urlretrieve(url, dest + ".part")
            os.rename(dest + ".part", dest)
            print(f"  ok ({os.path.getsize(dest) // 2**20} MiB)", flush=True)
            return
        except Exception as err:  # noqa: BLE001
            if attempt == RETRIES:
                raise
            delay = 5 * attempt
            print(f"  attempt {attempt} failed ({err}); retrying in {delay}s", flush=True)
            time.sleep(delay)


for url, dest in FILES:
    fetch(url, dest)
print("all models baked", flush=True)
