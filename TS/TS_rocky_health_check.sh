#!/bin/bash

# #############################################################################
#
# Script Name:  TS_rocky_health_check.sh
# Author:       Aaron Gruber <aaron@gizmobear.io>
# Date:         Jul 17, 2025
# Version:      1.0
#
# Description:  Performs a comprehensive health and security check on a TS
#               Rocky Linux system, covering security, system state,
#               storage, packages, and networking. The output is saved to
#               a report file in /tmp.
#
# Change Log:
#
#   1.0 - 2025-07-23 - Initial release.
#
# #############################################################################

OUTPUT="/tmp/health_report.txt"
> "$OUTPUT"

log() {
    echo -e "$1" | tee -a "$OUTPUT"
}

section() {
    echo -e "\n===== $1 =====" | tee -a "$OUTPUT"
}

# -------------------
# Security & Access Controls
# -------------------

section "SELinux Status"
log "Desired state: Enforcing"
SELINUX_STATUS=$(getenforce)
log "Current state: $SELINUX_STATUS"
[[ "$SELINUX_STATUS" == "Enforcing" ]] && log "PASS: SELinux is enforcing." || log "FAIL: SELinux is not enforcing."

section "SSH Service Status"
log "Desired state: Disabled, Inactive"
SSH_ENABLED=$(systemctl is-enabled sshd 2>/dev/null)
SSH_ACTIVE=$(systemctl is-active sshd 2>/dev/null)
log "Enabled: $SSH_ENABLED"
log "Active: $SSH_ACTIVE"
[[ "$SSH_ENABLED" == "disabled" && "$SSH_ACTIVE" == "inactive" ]] && log "PASS: SSH is disabled and inactive." || log "FAIL: SSH is not in proper state."

section "SSH Root Login"
log "Desired state: PermitRootLogin no"
SSH_ROOT_LOGIN=$(grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}')
log "Current setting: $SSH_ROOT_LOGIN"
[[ "$SSH_ROOT_LOGIN" == "no" ]] && log "PASS: Root login is disabled." || log "FAIL: Root login is enabled."

section "Wheel Group Members"
log "Desired state: No users in wheel group"
WHEEL_MEMBERS=$(getent group wheel | cut -d: -f4)
log "Members: $WHEEL_MEMBERS"
[[ -z "$WHEEL_MEMBERS" ]] && log "PASS: No users in wheel group." || log "FAIL: Wheel group contains users."

section "Login Shell Users"
log "Desired state: Only locadmin with UID >=1000 (excluding UID 65534)"
VALID_USERS=$(awk -F: '($3 >= 1000 && $3 != 65534 && $7 ~ /bash|sh/) {print $1}' /etc/passwd)
log "Current users: $VALID_USERS"
[[ "$VALID_USERS" == "locadmin" ]] && log "PASS: Only locadmin has a login shell." || log "FAIL: Unexpected login shell users present."

section "Sudoers Permissions"
log "Desired state: locadmin must have NOEXEC-only access to reboot and shutdown"
if grep -Fxq "locadmin ALL = (root) NOEXEC: /usr/sbin/reboot" /etc/sudoers && \
   grep -Fxq "locadmin ALL = (root) NOEXEC: /usr/sbin/shutdown" /etc/sudoers; then
    log "PASS: Sudoers permissions for locadmin are correctly configured."
else
    log "FAIL: Missing or incorrect sudoers entries for locadmin."
fi

# -------------------
# System State & Health
# -------------------

section "System Uptime"
log "Info only"
uptime -p | tee -a "$OUTPUT"

section "System Load"
log "Info only"
cat /proc/loadavg | tee -a "$OUTPUT"

section "Memory Usage"
log "Info only"
free -h | tee -a "$OUTPUT"

section "Zombie Processes"
log "Desired state: No zombie processes"
ZOMBIES=$(ps -eo stat | grep -c '^Z')
log "Zombie count: $ZOMBIES"
[[ "$ZOMBIES" -eq 0 ]] && log "PASS: No zombie processes." || log "FAIL: Zombie processes found."

section "Failed Services"
log "Desired state: No failed systemd units"
FAILED=$(systemctl --failed)
echo "$FAILED" | tee -a "$OUTPUT"
echo "$FAILED" | grep -q "0 loaded units listed." && log "PASS: No failed services." || log "FAIL: Failed services detected."

# -------------------
# Storage & Filesystem
# -------------------

section "Filesystem Usage (non-tmpfs)"
log "Desired state: All ≤ 85%, /mnt/backup ≤ 98%"
df -h -x tmpfs -x devtmpfs | tee -a "$OUTPUT" | while read -r line; do
    mount=$(echo "$line" | awk '{print $NF}')
    usage=$(echo "$line" | awk '{print $(NF-1)}' | tr -d '%')
    [[ "$mount" == "Mounted" ]] && continue
    if [[ "$mount" == "/mnt/backup" && "$usage" -le 98 ]]; then
        continue
    elif [[ "$mount" != "/mnt/backup" && "$usage" -le 85 ]]; then
        continue
    else
        log "FAIL: Filesystem $mount is over threshold: $usage%"
    fi
done

section "Inode Usage"
log "Desired state: All filesystems ≤ 85% inode usage"
df -ih | tee -a "$OUTPUT" | while read -r line; do
    usage=$(echo "$line" | awk '{print $(NF-2)}' | tr -d '%')
    mount=$(echo "$line" | awk '{print $NF}')
    [[ "$mount" == "Mounted" || -z "$usage" ]] && continue
    [[ "$usage" -gt 85 ]] && log "FAIL: Inode usage for $mount is $usage%" || continue
done

# -------------------
# Package & Update Compliance
# -------------------

section "Security Updates Check"
log "Desired state: No available security updates"
SEC_UPDATES=$(dnf updateinfo list security | grep -c "^SEC")
log "Security updates available: $SEC_UPDATES"
[[ "$SEC_UPDATES" -eq 0 ]] && log "PASS: No security updates pending." || log "FAIL: Security updates available."

section "Orphaned Packages"
log "Desired state: Only veeamdeployment and veeamtransport allowed"
EXTRAS=$(dnf repoquery --extras -q)
for pkg in $EXTRAS; do
    [[ "$pkg" == "veeamdeployment" || "$pkg" == "veeamtransport" ]] && continue
    log "FAIL: Unexpected orphaned package found: $pkg"
done
[[ -z "$EXTRAS" || "$EXTRAS" == *"veeamdeployment"* || "$EXTRAS" == *"veeamtransport"* ]] && log "PASS: No unauthorized orphaned packages."

# -------------------
# Networking
# -------------------

section "Firewalld Status"
log "Desired state: firewalld is active"
FIREWALLD=$(systemctl is-active firewalld)
log "Current state: $FIREWALLD"
[[ "$FIREWALLD" == "active" ]] && log "PASS: firewalld is active." || log "FAIL: firewalld is not active."

section "Listening Ports"
log "Info only"
ss -tulpn | tee -a "$OUTPUT"

section "NTP Synchronization"
log "Desired state: System clock synchronized: yes"
SYNCED=$(timedatectl status | grep "System clock synchronized" | awk '{print $4}')
log "System clock synchronized: $SYNCED"
[[ "$SYNCED" == "yes" ]] && log "PASS: System clock is synchronized." || log "FAIL: System clock is not synchronized."

section "Network Interface Statistics"
log "Info only"
ip -s link | tee -a "$OUTPUT"

section "Ethernet Tool Statistics"
log "Info only"
PRIMARY_IF=$(ip -o -4 route show to default | awk '{print $5}')
ethtool -S "$PRIMARY_IF" 2>/dev/null | tee -a "$OUTPUT"

# -------------------
# iSCSI Diagnostics (Info-only)
# -------------------

section "iSCSI Sessions"
log "Info only"
iscsiadm -m session 2>/dev/null | tee -a "$OUTPUT"

section "lsscsi Output"
log "Info only"
lsscsi -t 2>/dev/null | tee -a "$OUTPUT"

section "dmesg iSCSI Logs"
log "Info only"
dmesg | grep -i iscsi | tee -a "$OUTPUT"

section "journalctl iSCSI Logs"
log "Info only"
journalctl -b -k | grep -iE 'iscsi|reset|conn error' | tee -a "$OUTPUT"

# -------------------
# Final
# -------------------

section "Health Check Complete"
log "✅ Health check saved to: $OUTPUT"

exit 0
