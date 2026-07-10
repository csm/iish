# Isolated runner for scripts/verify-installers.sh (milestone 7). Builds
# iish from source, then a slim runtime image that runs it as a non-root
# user against real (and adversarial) installer scripts. Every
# verification run happens in a fresh `docker run --rm --network none`
# container, so a policy bug can do no lasting damage and never needs
# the network to be reproduced.

FROM mirror.gcr.io/library/rust:1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM mirror.gcr.io/library/debian:bookworm-slim
# bookworm-slim ships without a CA trust store, so iish's HTTPS client
# (correctly) refuses every TLS certificate as UnknownIssuer -- which
# blocks the live-install job's real downloads. ca-certificates gives
# it the standard roots any real system has; the offline suite runs
# with --network none and never uses them, so this only helps `--live`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --home-dir /home/tester --shell /bin/bash tester

COPY --from=builder /src/target/release/iish /usr/local/bin/iish
COPY scripts/installer-verify/run.sh scripts/installer-verify/run-corpus.sh scripts/installer-verify/run-adversarial.sh /usr/local/bin/
COPY scripts/installer-verify/fixtures/toy-installer.sh /opt/fixtures/toy-installer.sh
RUN chmod +x /usr/local/bin/run.sh /usr/local/bin/run-corpus.sh /usr/local/bin/run-adversarial.sh

USER tester
WORKDIR /home/tester
ENTRYPOINT ["/usr/local/bin/run.sh"]
