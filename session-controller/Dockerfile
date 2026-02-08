FROM rust:latest AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY session-controller/ ./
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/kasmvnc-session-controller /usr/local/bin/
COPY session-controller/controller-test.toml /etc/kasmvnc/controller.toml
ENV CONTROLLER_CONFIG=/etc/kasmvnc/controller.toml
EXPOSE 9090
CMD ["kasmvnc-session-controller"]
