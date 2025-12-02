FROM rust:1.82 as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

FROM debian:12-slim
WORKDIR /out

COPY --from=builder /app/target/release/libengine.so /out/libengine.so

CMD ["ls", "-lh", "/out"]
