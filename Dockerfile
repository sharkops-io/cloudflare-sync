FROM python:3.14-alpine3.24

# Standard library only: nothing to install.
COPY cloudflare_sync.py /app/cloudflare_sync.py

USER 65532:65532
ENTRYPOINT ["python3", "-I", "/app/cloudflare_sync.py"]
