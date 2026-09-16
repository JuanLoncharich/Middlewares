FROM python:3.12-alpine
RUN adduser -D -u 10004 vigil
COPY server.py /app/server.py
USER 10004:10004
ENV VIGIL_STUB_PORT=5000
EXPOSE 5000
CMD ["python", "/app/server.py"]
