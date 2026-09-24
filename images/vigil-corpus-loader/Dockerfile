FROM python:3.12-alpine

# Stdlib-only loader (urllib/json): no pip dependencies, small attack surface.
COPY load_corpus.py /app/load_corpus.py

USER 65534:65534

ENTRYPOINT ["python", "/app/load_corpus.py"]
