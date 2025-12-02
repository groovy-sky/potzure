# Build stage
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/honeypot ./cmd/honeypot

# Runtime stage
FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 honeypot \
    && mkdir -p /var/lib/honeypot/uploads \
    && touch /var/lib/honeypot/events.log \
    && chown -R honeypot:honeypot /var/lib/honeypot
WORKDIR /app
COPY --from=build /out/honeypot /app/honeypot
COPY internal/templates /app/internal/templates
RUN chown -R honeypot:honeypot /app
USER honeypot
EXPOSE 8080
VOLUME ["/var/lib/honeypot"]
ENTRYPOINT ["/app/honeypot"]
CMD ["-addr", ":8080", "-log", "/var/lib/honeypot/events.log", "-uploads", "/var/lib/honeypot/uploads"]
