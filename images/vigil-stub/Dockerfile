# Vigil scanner — six detection engines over the vigil-llm contract.
#
# Engines and their baked artifacts (all downloaded at build time; the
# container boots offline and stays stateless):
#   heuristics   pure regex (no artifacts)
#   yara         yara-python + vigil-llm rules vendored into /rules (Apache-2.0)
#   vector       all-MiniLM-L6-v2 int8 ONNX (/models, 23 MB) -> distributed Chroma
#   transformer  protectai/deberta-v3-base-prompt-injection fp32 ONNX (704 MB)
#   canonical    protectai/deberta-v3-base-prompt-injection-v2 fp32 ONNX (704 MB)
#   sentiment    VADER lexicon (pure-python package)
#
# deberta models ship fp32 deliberately: dynamic int8 quantization corrupts
# deberta-v3's disentangled attention (verified 2026-09-24).
FROM python:3.12-slim

RUN pip install --no-cache-dir \
      onnxruntime==1.20.1 \
      tokenizers==0.20.3 \
      numpy==2.1.3 \
      yara-python==4.5.4 \
      vaderSentiment==3.3.2

# Bake every model artifact. Retries absorb transient HF/CDN flakiness.
COPY download-models.py /tmp/download-models.py
RUN python /tmp/download-models.py && rm /tmp/download-models.py

# Vendored YARA rules (deadbits/vigil-llm data/yara, Apache-2.0).
COPY rules/ /rules/

COPY server.py scanners.py embedder.py /app/

RUN addgroup --gid 10004 vigil && adduser --uid 10004 --gid 10004 vigil
USER 10004:10004
ENV VIGIL_STUB_PORT=5000
EXPOSE 5000
CMD ["python", "/app/server.py"]
