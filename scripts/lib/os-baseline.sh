# scripts/lib/os-baseline.sh — the Ubuntu baseline every node's boot applies.
#
# Sourced, not executed, by all three boot scripts (GCP startup.sh, AWS startup.sh.tpl,
# Hetzner cloud-init), so a change to the OS baseline is made once. POSIX sh: cloud-init
# runs runcmd under dash, and the other two source it from bash.
#
# Each piece exists because Ubuntu 26.04 broke the boot without it:
#   - the Rust coreutils (uutils) are the default, and these scripts were written against
#     GNU behaviour (sha256sum --check --strict on every pin, stat, base64);
#   - a kernel fix arrives as a new package, which plain `apt-get upgrade` holds back;
#   - nothing reboots a node into an installed kernel fix;
#   - the AppArmor profile for `wg` blocks paths these nodes rely on.

# Every apt call waits for the dpkg lock: apt-daily and unattended-upgrades hold it at boot.
osb_apt() {
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -y -q "$@"
}

# Swap to GNU coreutils and fail if the swap did not take. apt counts coreutils-from-uutils
# as essential (coreutils pre-depends on it or the GNU variant), so the removal is named
# and allowed; coreutils stays provided because the GNU variant lands in the same transaction.
osb_gnu_coreutils() {
  dpkg-query -W -f='${Status}' coreutils-from-gnu 2>/dev/null | grep -q 'install ok installed' \
    || osb_apt --allow-remove-essential install coreutils-from-gnu coreutils-from-uutils- >/dev/null \
    || return 1
  ls --version | head -n 1 | grep -q 'GNU coreutils' && return 0
  echo "FATAL - GNU coreutils not active (coreutils-from-gnu)" >&2
  return 1
}

# Security and kernel updates. --with-new-pkgs installs new dependencies (a new kernel is
# linux-image-<version>) but never removes anything.
osb_security_upgrade() {
  osb_apt upgrade --with-new-pkgs
}

# A kernel fix only takes effect after a reboot, and nothing else reboots these nodes.
# Reboot in the quiet hours when an update requires it, even with a session open.
osb_auto_reboot() {
  cat > /etc/apt/apt.conf.d/52viaduct-auto-reboot <<'APTREBOOT'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
APTREBOOT
}

# The baseline, in order: package lists, GNU coreutils (before anything relies on them),
# updates, reboot policy.
osb_baseline() {
  osb_apt update && osb_gnu_coreutils && osb_security_upgrade && osb_auto_reboot
}

# Ubuntu 26.04's AppArmor profile for `wg` only reads under /etc/wireguard. It denies
# listing /run/wireguard/, where `wg show interfaces` looks for userspace sockets, so
# wg-quick down calls wg0 "not a WireGuard interface" and leaves it up and every later
# restart fails on "already exists". Allow that listing, plus any key file a node keeps
# outside /etc/wireguard (each argument, read-only), through the profile's local include.
# Call after wireguard-tools is installed.
osb_wg_apparmor() {
  [ -f /etc/apparmor.d/wg ] || return 0
  install -d -m 0755 /etc/apparmor.d/local
  {
    echo "/run/wireguard/ r,"
    for path in "$@"; do echo "$path r,"; done
  } > /etc/apparmor.d/local/wg
  apparmor_parser -r /etc/apparmor.d/wg
}
