# server-harden

One script that applies a security baseline to a fresh Ubuntu or Debian server:

- **Updates:** installs pending updates and turns on automatic security updates.
- **SSH:** key-only login, no root login, and only your account can log in.
- **Firewall (ufw):** blocks all incoming traffic except SSH from your LAN.
- **LAN isolation (optional):** stops the server from connecting to other devices on your home network, so a compromised app can't reach them.
- **Kernel:** ignores ICMP redirects and source-routed packets, and hides kernel addresses from non-root users.

It doesn't install Docker or any other software. Do that separately, after hardening.

Written for Ubuntu 22.04+ and Debian 12+.

## Before you run it

You need an SSH key on the server, because the script turns password login off. It checks for one and stops if there isn't one.

On Windows (PowerShell):

```powershell
ssh-keygen -t ed25519
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub | ssh you@SERVER_IP "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

On macOS or Linux: `ssh-keygen -t ed25519 && ssh-copy-id you@SERVER_IP`

Or add your public key to GitHub and choose **Import SSH key → from GitHub** in the Ubuntu installer.

If the server is a VM, take a snapshot or checkpoint first.

## Run it

Download it, read it, then run it:

```bash
curl -fsSL https://raw.githubusercontent.com/TheJagg/server-harden/main/harden.sh -o harden.sh
less harden.sh
sudo bash harden.sh
```

To pin a version, download from a release tag instead of `main`, e.g. `.../server-harden/v0.1.0/harden.sh`.

The script prints what it will do and asks before changing anything. When it finishes, **open a new terminal and check you can still SSH in** before closing the old one.

## Options

| Option | What it does |
|---|---|
| `--user NAME` | The account you SSH in as. Default: whoever ran `sudo`. |
| `--ssh-from CIDR` | Allow SSH from this network or address. Repeatable. Default: the server's LAN subnet. |
| `--isolate-lan` | Block outgoing connections to the rest of the LAN. The router and LAN DNS servers stay reachable. |
| `--allow-out ADDR` | With `--isolate-lan`, still allow this address or subnet (e.g. a NAS you monitor). Repeatable. |
| `--reboot-at HH:MM` | Reboot automatically at this time when an update needs it. Default: never. |
| `-y`, `--yes` | Don't ask for confirmation. |

Examples:

```bash
# Typical home server: SSH from the LAN only, can't reach other home devices except the NAS
sudo bash harden.sh --isolate-lan --allow-out 192.168.1.20 --reboot-at 04:00

# Also allow SSH over Tailscale
sudo bash harden.sh --ssh-from 192.168.1.0/24 --ssh-from 100.64.0.0/10
```

## Re-running

It's safe to run again, for example with different options. Each run rewrites its own files and **resets ufw to exactly what the options say**, so firewall rules you added by hand are removed (ufw keeps a backup in `/etc/ufw/`).

## Files it writes

| File | Purpose |
|---|---|
| `/etc/ssh/sshd_config.d/10-harden.conf` | SSH settings |
| `/etc/apt/apt.conf.d/20auto-upgrades` | Turns on daily automatic updates |
| `/etc/apt/apt.conf.d/52harden-reboot` | Automatic reboot time (only with `--reboot-at`) |
| `/etc/sysctl.d/90-harden.conf` | Kernel network settings |
| ufw rules | Firewall |

## Locked out?

From the VM or server console:

```bash
sudo rm /etc/ssh/sshd_config.d/10-harden.conf && sudo systemctl restart ssh
sudo ufw disable
```

## Things to know

- **Docker bypasses ufw.** Ports published with `-p 8080:80` are reachable even though ufw blocks incoming traffic, and traffic from containers isn't covered by `--isolate-lan`. Publish ports on `127.0.0.1` only (`-p 127.0.0.1:8080:80`), and for container isolation use a VLAN or a firewall rule on the router or hypervisor.
- **IPv4 only** for `--ssh-from`, `--allow-out` and `--isolate-lan`. Incoming IPv6 is still blocked by ufw's default policy.
- **One login account.** `AllowUsers` is set to `--user`. To allow more accounts, edit `/etc/ssh/sshd_config.d/10-harden.conf`.
