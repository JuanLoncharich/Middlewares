# Vigil scanner stub — heuristics + optional distributed-Chroma vector scan.
#
# The vector scanner embeds prompts with all-MiniLM-L6-v2 (same model as the
# Vigil corpora loaded into Chroma by images/vigil-corpus-loader), so the
# ONNX model + tokenizer are baked at build time: the container stays
# stateless and boots offline (no runtime model downloads).
FROM python:3.12-slim

# Pin the runtime deps; onnxruntime CPU inference only.
RUN pip install --no-cache-dir \
      onnxruntime==1.20.1 \
      tokenizers==0.20.3 \
      numpy==2.1.3

# all-MiniLM-L6-v2, quantized ONNX export (int8, ~23MB) + its tokenizer, from
# the Xenova mirrors of sentence-transformers/all-MiniLM-L6-v2.
RUN mkdir -p /models && python -c "\
import urllib.request;\
urllib.request.urlretrieve('https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/tokenizer.json', '/models/tokenizer.json');\
urllib.request.urlretrieve('https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/onnx/model_quantized.onnx', '/models/model_quantized.onnx')"

RUN addgroup --gid 10004 vigil && adduser --uid 10004 --gid 10004 vigil
COPY server.py /app/server.py
USER 10004:10004
ENV VIGIL_STUB_PORT=5000
EXPOSE 5000
CMD ["python", "/app/server.py"]
