# ITSOC Demo Target Container

Stage C / C3-T1 disposable demonstration target for automated firewall response testing.

## Overview
This container runs a lightweight Debian Linux environment with `nftables` and key-only `openssh-server`, serving as a realistic, isolated network firewall target.

## Binding Safety Guardrails
Per `hive/stage-c/GUARDRAILS.md`:
1. **Loopback Only**: Port 22 is published strictly to `127.0.0.1:2222` (`-p 127.0.0.1:2222:22`).
2. **Never Host Network**: NEVER `--net=host` / `--network host`. The container operates in its own isolated network namespace.
3. **No Socket or Host Mounts**: No Docker socket mounts (`/var/run/docker.sock`), no host filesystem mounts.
4. **Least Privilege**: Uses `--cap-add=NET_ADMIN` only (never `--privileged`).
5. **Private Key Safety**: Private keys (`target_ed25519`) reside strictly on the host under gitignored `console/.soc/keys/` with mode `0600`. Only the public key (`target_ed25519.pub`) is mounted read-only to `/root/.ssh/authorized_keys:ro`.

## Commands Executed on Target
- **Bootstrap**:
  ```bash
  nft add table inet itsoc
  nft add chain inet itsoc filter '{ type filter hook input priority -10; policy accept; }'
  nft add set inet itsoc blacklist '{ type ipv4_addr; flags interval; }'
  nft add rule inet itsoc filter ip saddr @blacklist drop comment "itsoc-block-set-rule"
  ```
- **Execute (Block IP)**:
  ```bash
  nft add element inet itsoc blacklist '{ <ip> comment "itsoc:appr-<id>" }'
  ```
- **Verify**:
  ```bash
  nft list table inet itsoc
  ```
- **Revoke (Unblock IP)**:
  ```bash
  nft delete element inet itsoc blacklist '{ <ip> }'
  ```

## Running the Target
When Docker daemon is running:
```bash
./demo/target/run.sh
```
