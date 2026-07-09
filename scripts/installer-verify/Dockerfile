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
RUN useradd --create-home --home-dir /home/tester --shell /bin/bash tester

COPY --from=builder /src/target/release/iish /usr/local/bin/iish
COPY scripts/installer-verify/run.sh scripts/installer-verify/run-corpus.sh scripts/installer-verify/run-adversarial.sh /usr/local/bin/
COPY scripts/installer-verify/fixtures/toy-installer.sh /opt/fixtures/toy-installer.sh
RUN chmod +x /usr/local/bin/run.sh /usr/local/bin/run-corpus.sh /usr/local/bin/run-adversarial.sh

USER tester
WORKDIR /home/tester
ENTRYPOINT ["/usr/local/bin/run.sh"]
