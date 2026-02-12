FROM rust:1.93 AS dev-base
        RUN rustup component add rustfmt
        RUN rustup component add clippy

        ENV CARGO_TARGET_DIR=/proxy-target

        # build dependencies
        COPY Cargo.toml ./
        COPY src/_deps.rs ./src/_deps.rs
        RUN cargo build --bin _deps

        WORKDIR /proxy
        CMD [ "cargo", "run", "--bin", "proxy", "--frozen" ]

        EXPOSE 443

FROM dev-base AS build
        COPY . .
