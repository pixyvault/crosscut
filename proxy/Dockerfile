FROM rust:1.93 AS proxy-rust
        RUN cargo install cargo-chef --locked
        RUN rustup component add rustfmt
        RUN rustup component add clippy
        ENV CARGO_TARGET_DIR=/proxy-target
        WORKDIR /proxy

FROM proxy-rust AS planner
        # prepare dependencies
        COPY . .
        RUN cargo update
        RUN cargo chef prepare --recipe-path recipe.json

FROM proxy-rust AS dev-base
        # build dependencies
        COPY --from=planner /proxy/recipe.json recipe.json
        RUN cargo chef cook --recipe-path recipe.json

        CMD [ "cargo", "run", "--frozen", "--bin", "proxy" ]
        EXPOSE 443

FROM dev-base AS build
        COPY . .
