# syntax=docker/dockerfile:1
#
# ecomsec container image: static musl binary on distroless, non-root.
#
#   docker build -t ecomsec .
#   docker run --rm -v /var/www/shop:/shop:ro -v ecomsec-state:/state ecomsec scan --skip-remote
#
# See docker/README.md for details.

# ---------------------------------------------------------------- build
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# Alpine's Rust targets musl and links statically by default.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p ecomsec \
    && cp target/release/ecomsec /usr/local/bin/ecomsec \
    && /usr/local/bin/ecomsec --version
# Mount points owned by the non-root runtime user (distroless has no shell).
RUN mkdir -p /out/shop /out/state && chown -R 65532:65532 /out/state

# ---------------------------------------------------------------- runtime
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="ecomsec" \
      org.opencontainers.image.description="Read-only Kompromittierungs-Check für JTL-Shop 5, Shopware 6, WooCommerce, Magento 2 und Shopify" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/liohtml/ecom-sec"

COPY --from=build /usr/local/bin/ecomsec /usr/local/bin/ecomsec
COPY --from=build /out/shop /shop
COPY --from=build --chown=65532:65532 /out/state /state

# Shop files are mounted read-only at /shop; risk acceptance, baseline and
# history live in /state.
ENV ECOMSEC_STATE_DIR=/state
VOLUME ["/shop", "/state"]
WORKDIR /shop
USER 65532:65532
EXPOSE 8787

ENTRYPOINT ["ecomsec"]
CMD ["--help"]
