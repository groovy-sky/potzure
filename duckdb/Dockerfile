# Use a minimal Debian-based image
FROM debian:bookworm-slim

# Use /bin/sh as the default shell
SHELL ["/bin/sh", "-c"]

# Install required tools (curl + unzip) then clean up apt cache
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates \
    && mkdir -p /etc/pki/tls/certs \
    && ln -s /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt

# Download the specified DuckDB CLI zip and store it in the image
# (kept as a zip file as requested)
RUN mkdir -p /opt/duckdb \
    && curl -sSL \
       "https://github.com/duckdb/duckdb/releases/download/v1.4.2/duckdb_cli-linux-amd64.zip" \
       -o /opt/duckdb/duckdb_cli-linux-amd64.zip

# (Optional) also extract the binary so the container is directly runnable
RUN unzip -p /opt/duckdb/duckdb_cli-linux-amd64.zip duckdb > /usr/local/bin/duckdb \
    && chmod +x /usr/local/bin/duckdb

# Default command: start a shell (sh)
CMD ["duckdb"]