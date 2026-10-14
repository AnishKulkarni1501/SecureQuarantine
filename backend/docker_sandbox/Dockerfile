FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends coreutils strace \
    && rm -rf /var/lib/apt/lists/*

COPY run-elf.sh /usr/local/bin/sq-run-elf
RUN chmod 0555 /usr/local/bin/sq-run-elf

ENTRYPOINT ["/usr/local/bin/sq-run-elf"]
