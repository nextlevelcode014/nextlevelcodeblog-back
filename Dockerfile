FROM rust:latest AS builder
WORKDIR /backend_nextlevelcodeblog
COPY Cargo.toml Cargo.lock ./
RUN mkdir src
RUN echo 'fn main() {}' > src/main.rs
RUN cargo build --release
RUN rm -rf src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt update && \
    apt install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /backend_nextlevelcodeblog/target/release/backend_nextlevelcodeblog ./backend_nextlevelcodeblog
CMD ["./backend_nextlevelcodeblog"]
