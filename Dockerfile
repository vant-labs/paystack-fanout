FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx
COPY migrations ./migrations
COPY src ./src
COPY static ./static
COPY templates ./templates
ENV SQLX_OFFLINE=true
RUN cargo build --release

FROM debian:bookworm-slim
RUN groupadd --system --gid 10001 fanout && useradd --system --uid 10001 --gid fanout fanout
COPY --from=builder /build/target/release/paystack-fanout /usr/local/bin/paystack-fanout
USER fanout
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/paystack-fanout"]
