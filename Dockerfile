ARG RUST_VERSION=1.97
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --no-create-home identity
COPY --from=build /build/target/release/saas-identity /usr/local/bin/saas-identity
USER 10001
EXPOSE 3041
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/saas-identity"]
