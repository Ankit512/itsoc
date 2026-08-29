#!/bin/sh
set -e

# Generate host keys if not present
ssh-keygen -A


# Initialize nftables base table, chain, set, and enforcement rule
nft add table inet itsoc
nft add chain inet itsoc filter '{ type filter hook input priority -10; policy accept; }'
nft add set inet itsoc blacklist '{ type ipv4_addr; flags interval; }'
nft add rule inet itsoc filter ip saddr @blacklist drop comment \"itsoc-block-set-rule\"

# Verify ruleset initialized properly and enforcement drop rule is active
if ! nft list chain inet itsoc filter | grep -q '@blacklist drop'; then
    echo "ERROR: itsoc blacklist drop rule is missing from filter chain" >&2
    exit 1
fi

exec /usr/sbin/sshd -D -e
