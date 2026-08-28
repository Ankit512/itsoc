#!/bin/sh
set -e

# Generate host keys if not present
ssh-keygen -A

# Ensure authorized_keys has safe permissions if mounted
if [ -f /root/.ssh/authorized_keys ]; then
    chmod 600 /root/.ssh/authorized_keys
fi

# Initialize nftables base table and set
nft add table inet itsoc 2>/dev/null || true
nft add chain inet itsoc filter '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true
nft add set inet itsoc blacklist '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
nft add rule inet itsoc filter ip saddr @blacklist drop comment "itsoc:block-set-rule" 2>/dev/null || true

exec /usr/sbin/sshd -D -e
