# ==============================================================================
# ITSOC Phase C3 Disposable Demo Target Container
#
# BINDING GUARDRAILS (hive/stage-c/GUARDRAILS.md):
#   - Base image: debian:bookworm-slim
#   - Key-only SSH authentication (no passwords, no interactive prompts)
#   - Private SSH key NEVER enters image, container, or logs
#   - Network: isolated netns (NEVER --net=host)
#   - Capabilities: --cap-add=NET_ADMIN ONLY (NEVER --privileged)
#   - Default seccomp profile preserved
# ==============================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    openssh-server \
    iproute2 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set up sshd runtime directory and root ssh folder
RUN mkdir -p /var/run/sshd /root/.ssh && chmod 700 /root/.ssh

# Configure key-only SSH daemon
RUN printf "Port 22\n\
PermitRootLogin prohibit-password\n\
PasswordAuthentication no\n\
KbdInteractiveAuthentication no\n\
PubkeyAuthentication yes\n\
AuthorizedKeysFile .ssh/authorized_keys\n\
StrictModes yes\n\
PrintMotd no\n\
UsePAM no\n" > /etc/ssh/sshd_config.d/itsoc-target.conf

EXPOSE 22

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
