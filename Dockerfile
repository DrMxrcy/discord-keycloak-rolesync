# Stage 1: Set up the build environment
FROM debian:12-slim AS builder

RUN apt-get update && apt-get install --no-install-suggests --no-install-recommends --yes \
    python3 \
    python3-pip \
    python3-venv \
    git

WORKDIR /app
COPY requirements.txt /app/

# Create a virtual environment and install dependencies
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install -r requirements.txt

# Stage 2: Run in a distroless image
FROM gcr.io/distroless/python3-debian12

LABEL org.opencontainers.image.title="Discord to Keycloak Role Sync"
LABEL org.opencontainers.image.description="Synchronises membership of Discord roles to Keycloak groups"
LABEL org.opencontainers.image.authors="Ike Johnson-Woods <contact@ike.au>"
LABEL org.opencontainers.image.source=https://github.com/NotActuallyTerry/discord-keycloak-rolesync
LABEL org.opencontainers.image.license=MPL-2.0

COPY --from=builder /app /app
COPY app.py /app/app.py
WORKDIR /app

ENTRYPOINT ["/app/venv/bin/python", "app.py"]
