FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
COPY bridgelab/ bridgelab/
RUN pip install --no-cache-dir .

COPY infra/poison/ /data/poison/

ENV KEYCLOAK_URL=http://keycloak:8080
ENV AWS_ENDPOINT_URL=http://localstack:4566
ENV AGENT_MODE=mock
ENV POISON_DOC=/data/poison/malicious_document.md

ENTRYPOINT ["bridgelab-attack"]
CMD ["--mode", "mock"]
