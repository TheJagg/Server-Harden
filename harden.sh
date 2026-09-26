#!/usr/bin/env bash
# harden.sh: baseline security for a fresh Ubuntu/Debian server.
#
# Read it before running it. Safe to re-run: each run rewrites the same files
# and resets the firewall to exactly what the options say.
set -euo pipefail

VERSION="0.1.0"

usage() {
  cat <<'EOF'
Usage: sudo bash harden.sh [options]

Options:
  --user NAME         The account you SSH in as (default: the user who ran sudo)
  --ssh-from CIDR     Allow SSH from this IPv4 network or address. Repeatable.
                      (default: the server's LAN subnet, e.g. 192.168.1.0/24)
  --isolate-lan       Block this server from connecting to other devices on the LAN
                      (the router and LAN DNS servers stay reachable)
  --allow-out ADDR    With --isolate-lan: still allow this IPv4 address or CIDR. Repeatable.
  --reboot-at HH:MM   Reboot automatically at this time when an update needs it
                      (default: never; you reboot yourself)
  -y, --yes           Don't ask for confirmation
  -h, --help          Show this help
EOF
}

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ─── IPv4 helpers ────────────────────────────────────────────────────

is_ipv4() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]
}

ip_to_int() {
  local IFS=. a b c d
  read -r a b c d <<<"$1"
  echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}

# in_cidr 192.168.1.5 192.168.1.0/24 → true. A bare address counts as /32.
in_cidr() {
  local ip=$1 net=${2%/*} bits=32
  [[ $2 == */* ]] && bits=${2#*/}
  local mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  (( ($(ip_to_int "$ip") & mask) == ($(ip_to_int "$net") & mask) ))
}

# ─── Options ─────────────────────────────────────────────────────────

user="${SUDO_USER:-}"
ssh_from=()
isolate_lan=false
allow_out=()
reboot_at=""
assume_yes=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)        user="${2:?--user needs a value}"; shift 2 ;;
    --ssh-from)    ssh_from+=("${2:?--ssh-from needs a value}"); shift 2 ;;
    --isolate-lan) isolate_lan=true; shift ;;
    --allow-out)   allow_out+=("${2:?--allow-out needs a value}"); shift 2 ;;
    --reboot-at)   reboot_at="${2:?--reboot-at needs a value}"; shift 2 ;;
    -y|--yes)      assume_yes=true; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             usage >&2; die "unknown option: $1" ;;
  esac
done

# ─── Preflight: every check happens before anything is changed ───────

[[ $EUID -eq 0 ]] || die "run it with sudo: sudo bash harden.sh"

# shellcheck source=/dev/null
. /etc/os-release
[[ ${ID:-} == ubuntu || ${ID:-} == debian || ${ID_LIKE:-} == *debian* ]] \
  || die "only Ubuntu and Debian are supported (found: ${PRETTY_NAME:-unknown})"

command -v sshd >/dev/null || die "OpenSSH server isn't installed: sudo apt install openssh-server"

[[ -n $user ]] || die "couldn't tell which account you log in as; pass --user NAME"
[[ $user != root ]] || die "--user must be your normal account, not root"
home=$(getent passwd "$user" | cut -d: -f6) || die "user '$user' doesn't exist"

# Password login is about to be turned off, so a working key must already exist.
keys="$home/.ssh/authorized_keys"
if ! grep -vE '^[[:space:]]*#' "$keys" 2>/dev/null \
    | grep -qE '(ssh-(ed25519|rsa)|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+) '; then
  die "no SSH public key in $keys.
       Add yours first (see the README), or you'd be locked out once password login is off."
fi

[[ -z $reboot_at || $reboot_at =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] \
  || die "--reboot-at must look like 04:00"

# sshd refuses to run -t/-T without this directory, which socket activation may not have created yet.
mkdir -p /run/sshd
ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
ssh_port=${ssh_port:-22}

gateway="" lan_dev=""
read -r gateway lan_dev < <(ip -4 route show default | awk '{
  for (i = 1; i <= NF; i++) { if ($i == "via") g = $(i + 1); if ($i == "dev") d = $(i + 1) }
  print g, d; exit }') || true
lan_cidr=""
if [[ -n $lan_dev ]]; then
  lan_cidr=$(ip -4 route show dev "$lan_dev" scope link proto kernel | awk '{ print $1; exit }')
fi

if [[ ${#ssh_from[@]} -eq 0 ]]; then
  [[ -n $lan_cidr ]] || die "couldn't detect the LAN subnet; pass --ssh-from, e.g. --ssh-from 192.168.1.0/24"
  ssh_from=("$lan_cidr")
fi
for c in "${ssh_from[@]}" "${allow_out[@]}"; do
  is_ipv4 "$c" || die "not an IPv4 address or CIDR: $c"
done

lan_allow=()
if $isolate_lan; then
  [[ -n $lan_cidr && -n $gateway ]] || die "couldn't detect the LAN subnet and router needed for --isolate-lan"
  lan_allow=("$gateway")
  # Keep LAN DNS servers (e.g. a Pi-hole) reachable, or name lookups stop working.
  while read -r dns; do
    if in_cidr "$dns" "$lan_cidr"; then lan_allow+=("$dns"); fi
  done < <(resolvectl dns 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
  lan_allow+=("${allow_out[@]}")
  mapfile -t lan_allow < <(printf '%s\n' "${lan_allow[@]}" | sort -u)
elif [[ ${#allow_out[@]} -gt 0 ]]; then
  warn "--allow-out only has an effect together with --isolate-lan"
fi

# Warn if you're connected from somewhere the new firewall won't let back in.
while read -r peer; do
  allowed=false
  for c in "${ssh_from[@]}"; do
    if in_cidr "$peer" "$c"; then allowed=true; fi
  done
  $allowed || warn "you're connected over SSH from $peer, which isn't covered by --ssh-from.
         This session stays open, but new SSH connections from there will be blocked."
done < <(ss -Htn state established "( sport = :$ssh_port )" \
  | awk '{ print $4 }' | sed -E 's/:[0-9]+$//; s/^\[?(::ffff:)?//; s/\]$//' \
  | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u || true)

# ─── Confirm ─────────────────────────────────────────────────────────

plan=("Install updates and turn on automatic security updates")
if [[ -n $reboot_at ]]; then
  plan+=("Reboot automatically at $reboot_at when an update needs it")
fi
plan+=(
  "SSH: keys only, no root login, only '$user' may log in"
  "Firewall: block all incoming except SSH (port $ssh_port) from ${ssh_from[*]}"
)
if $isolate_lan; then
  plan+=("Firewall: block outgoing connections to $lan_cidr, except ${lan_allow[*]}")
fi
plan+=("Kernel: ignore ICMP redirects and source-routed packets, hide kernel addresses")

printf '\nharden.sh %s will:\n' "$VERSION"
printf '  - %s\n' "${plan[@]}"
echo

if ! $assume_yes; then
  [[ -r /dev/tty ]] || die "no terminal to ask for confirmation; re-run with --yes"
  read -rp "Continue? [y/N] " answer </dev/tty
  [[ $answer == [yY]* ]] || die "cancelled, nothing was changed"
fi

# ─── 1. Updates ──────────────────────────────────────────────────────

log "Installing updates (this can take a few minutes)"
export DEBIAN_FRONTEND=noninteractive
# Keep existing config files when packages ship new versions.
apt_opts=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
apt-get update -q
apt-get "${apt_opts[@]}" full-upgrade
apt-get "${apt_opts[@]}" install ufw unattended-upgrades

log "Turning on automatic security updates"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
reboot_conf=/etc/apt/apt.conf.d/52harden-reboot
if [[ -n $reboot_at ]]; then
  cat >"$reboot_conf" <<EOF
// Written by harden.sh
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "$reboot_at";
EOF
else
  rm -f "$reboot_conf"
fi
systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true

# ─── 2. SSH ──────────────────────────────────────────────────────────

log "Locking down SSH"
ssh_conf=/etc/ssh/sshd_config.d/10-harden.conf
ssh_backup=""
if [[ -f $ssh_conf ]]; then
  ssh_backup=$(mktemp)
  cp "$ssh_conf" "$ssh_backup"
fi
cat >"$ssh_conf" <<EOF
# Written by harden.sh. sshd uses the first value it reads for each setting, and
# this directory is read before sshd_config, so these win over anything later
# (including cloud-init's 50-cloud-init.conf).
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication yes
AllowUsers $user
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
EOF
chmod 644 "$ssh_conf"

if ! sshd -t; then
  if [[ -n $ssh_backup ]]; then cp "$ssh_backup" "$ssh_conf"; else rm -f "$ssh_conf"; fi
  die "the new SSH config failed validation and was rolled back; SSH is unchanged"
fi
# Reload keeps existing sessions open. If sshd isn't running (socket activation),
# it picks up the new config on the next connection.
systemctl try-reload-or-restart ssh.service

if ! sshd -T | grep -qx 'passwordauthentication no'; then
  warn "sshd still reports password login as enabled. Check that /etc/ssh/sshd_config
         has 'Include /etc/ssh/sshd_config.d/*.conf' near the top."
fi

# ─── 3. Firewall ─────────────────────────────────────────────────────

log "Configuring the firewall"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
for c in "${ssh_from[@]}"; do
  ufw allow from "$c" to any port "$ssh_port" proto tcp comment 'SSH' >/dev/null
done
if $isolate_lan; then
  # ufw checks rules in order, so the exceptions go before the block.
  for a in "${lan_allow[@]}"; do
    ufw allow out to "$a" comment 'LAN exception' >/dev/null
  done
  ufw deny out to "$lan_cidr" comment 'LAN isolation' >/dev/null
fi
ufw --force enable >/dev/null

# ─── 4. Kernel network settings ──────────────────────────────────────

log "Applying kernel settings"
cat >/etc/sysctl.d/90-harden.conf <<'EOF'
# Written by harden.sh. Leaves net.ipv4.ip_forward alone, because Docker needs it.

# Ignore ICMP redirects and source-routed packets (both can reroute traffic)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Hide kernel addresses and the kernel log from non-root users
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF
sysctl --quiet --system >/dev/null

# ─── Done ────────────────────────────────────────────────────────────

server_ip=$(hostname -I | awk '{ print $1 }')
log "Done"
cat <<EOF

Before closing this session, open a NEW terminal and check you can still log in:

    ssh $user@${server_ip:-<server-ip>}

If that fails, fix it from this session (or the VM console):

    sudo rm $ssh_conf && sudo systemctl restart ssh
    sudo ufw disable

EOF
ufw status verbose
if [[ -f /var/run/reboot-required ]]; then
  echo
  warn "a reboot is needed to finish installing updates: sudo reboot"
fi
