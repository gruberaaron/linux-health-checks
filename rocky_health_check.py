#!/usr/bin/env python3

# #############################################################################
#
# Script Name:  rocky_health_check.py
# Author:       Aaron Gruber <aaron@gizmobear.io>
# Date:         Jul 25, 2025
# Version:      1.0
#
# Description:  Performs a comprehensive health and security check on a
#               Rocky Linux system, covering security, system state,
#               storage, packages, and networking. The output is saved to
#               a report file in /tmp.
#
# Change Log:
#
#   1.0 - 2025-07-25 - Initial release (Python conversion).
#
# #############################################################################

import os
import re
import subprocess
import sys
import logging
import pathlib

# Configuration constants
OUTPUT = "/tmp/health_report.txt"

# Setup logging
def setup_logging():
    """Set up logging to both console and file"""
    # Ensure directory exists
    output_dir = os.path.dirname(OUTPUT)
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Clear previous log file
    open(OUTPUT, 'w').close()

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(console_handler)

    # File handler
    file_handler = logging.FileHandler(OUTPUT)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    root_logger.addHandler(file_handler)

    return root_logger

# Initialize logger
logger = setup_logging()

def log(message):
    """Log a message to both stdout and the output file"""
    logger.info(message)

def section(title):
    """Create a section header"""
    message = f"\n===== {title} ====="
    logger.info(message)

def run_command(command, shell=False):
    """Run a shell command and return the output"""
    try:
        # Log command for debugging if needed
        # log(f"Running command: {command}")

        if shell:
            # Use shell=True only when necessary (like pipe operations)
            result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=60)
        else:
            # Ensure command is a list when shell=False
            if isinstance(command, str):
                command = command.split()
            result = subprocess.run(command, text=True, capture_output=True, timeout=60)

        # Check if the command was successful
        if result.returncode != 0:
            error_msg = f"Command failed with exit code {result.returncode}: {result.stderr}"
            # We want to log the error but still return the output for some commands
            # that might partially succeed
            if not shell:  # For shell commands, we often check exit code separately
                return error_msg

        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out after 60 seconds"
    except Exception as e:
        return f"Error executing command: {str(e)}"

def run_command_to_output(command, shell=False):
    """Run a command and output to both stdout and the report file"""
    try:
        output = run_command(command, shell)

        # Log the output using our logger
        log(output)

        # Check if the output indicates an error
        if output.startswith("Error executing command") or output.startswith("Command failed") or output.startswith("Command timed out"):
            log(f"WARNING: Command execution issue: {command if isinstance(command, str) else ' '.join(command)}")

        return output
    except Exception as e:
        error_msg = f"ERROR: Failed to run command: {str(e)}"
        log(error_msg)
        return error_msg

# -------------------
# Security & Access Controls
# -------------------

def check_selinux():
    section("SELinux Status")
    log("Desired state: Enforcing")
    selinux_status = run_command(["getenforce"])
    log(f"Current state: {selinux_status}")
    if selinux_status == "Enforcing":
        log("PASS: SELinux is enforcing.")
    else:
        log("FAIL: SELinux is not enforcing.")

def check_ssh_service():
    section("SSH Service Status")
    log("Desired state: Disabled, Inactive")
    ssh_enabled = run_command(["systemctl", "is-enabled", "sshd"], shell=False)
    ssh_active = run_command(["systemctl", "is-active", "sshd"], shell=False)
    log(f"Enabled: {ssh_enabled}")
    log(f"Active: {ssh_active}")
    if ssh_enabled == "disabled" and ssh_active == "inactive":
        log("PASS: SSH is disabled and inactive.")
    else:
        log("FAIL: SSH is not in proper state.")

def check_ssh_root_login():
    section("SSH Root Login")
    log("Desired state: PermitRootLogin no")
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            for line in f:
                if re.match(r'^PermitRootLogin\s+', line, re.IGNORECASE):
                    ssh_root_login = line.split()[1]
                    break
            else:
                ssh_root_login = "Not set"
    except:
        ssh_root_login = "File not accessible"

    log(f"Current setting: {ssh_root_login}")
    if ssh_root_login == "no":
        log("PASS: Root login is disabled.")
    else:
        log("FAIL: Root login is enabled.")

def check_wheel_group():
    section("Wheel Group Members")
    log("Desired state: No users in wheel group")
    wheel_members = run_command("getent group wheel | cut -d: -f4", shell=True)
    log(f"Members: {wheel_members}")
    if not wheel_members:
        log("PASS: No users in wheel group.")
    else:
        log("FAIL: Wheel group contains users.")

def check_login_shell_users():
    section("Login Shell Users")
    log("Desired state: Only locadmin with UID >=1000 (excluding UID 65534)")
    valid_users = run_command("awk -F: '($3 >= 1000 && $3 != 65534 && $7 ~ /bash|sh/) {print $1}' /etc/passwd", shell=True)
    log(f"Current users: {valid_users}")
    if valid_users == "locadmin":
        log("PASS: Only locadmin has a login shell.")
    else:
        log("FAIL: Unexpected login shell users present.")

def check_sudoers_permissions():
    section("Sudoers Permissions")
    log("Desired state: locadmin must have NOEXEC-only access to reboot and shutdown")

    # Use direct command status checks instead of string comparisons
    try:
        reboot_check = subprocess.run(["grep", "-Fxq", "locadmin ALL = (root) NOEXEC: /usr/sbin/reboot", "/etc/sudoers"], 
                                    capture_output=True)
        shutdown_check = subprocess.run(["grep", "-Fxq", "locadmin ALL = (root) NOEXEC: /usr/sbin/shutdown", "/etc/sudoers"], 
                                      capture_output=True)

        if reboot_check.returncode == 0 and shutdown_check.returncode == 0:
            log("PASS: Sudoers permissions for locadmin are correctly configured.")
        else:
            log("FAIL: Missing or incorrect sudoers entries for locadmin.")
    except Exception as e:
        log(f"ERROR: Could not check sudoers file: {e}")
        log("FAIL: Unable to verify sudoers entries.")

# -------------------
# System State & Health
# -------------------

def check_system_uptime():
    section("System Uptime")
    log("Info only")
    run_command_to_output(["uptime", "-p"])

def check_system_load():
    section("System Load")
    log("Info only")
    with open("/proc/loadavg", "r") as f:
        loadavg = f.read().strip()
    log(loadavg)

def check_memory_usage():
    section("Memory Usage")
    log("Info only")
    run_command_to_output(["free", "-h"])

def check_zombie_processes():
    section("Zombie Processes")
    log("Desired state: No zombie processes")
    zombies = run_command("ps -eo stat | grep -c '^Z'", shell=True)
    log(f"Zombie count: {zombies}")
    if zombies == "0":
        log("PASS: No zombie processes.")
    else:
        log("FAIL: Zombie processes found.")

def check_failed_services():
    section("Failed Services")
    log("Desired state: No failed systemd units")
    failed = run_command_to_output(["systemctl", "--failed"])
    if "0 loaded units listed" in failed:
        log("PASS: No failed services.")
    else:
        log("FAIL: Failed services detected.")

# -------------------
# Storage & Filesystem
# -------------------

def check_filesystem_usage():
    section("Filesystem Usage (non-tmpfs)")
    log("Desired state: All ≤ 85%, /mnt/backup ≤ 98%")
    df_output = run_command_to_output("df -h -x tmpfs -x devtmpfs", shell=True)

    # Check if command was successful
    if df_output.startswith("Error") or df_output.startswith("Command failed"):
        log("WARNING: Could not check filesystem usage")
        return

    lines = df_output.split('\n')
    if len(lines) <= 1:  # Only header or no output
        log("WARNING: No filesystem data available")
        return

    # Track if we've found any failures to report a PASS if none
    failures = False

    for line in lines[1:]:  # Skip header line
        parts = line.split()
        if not parts:
            continue

        try:
            mount = parts[-1]
            usage_str = parts[-2].rstrip('%')

            if not usage_str.isdigit():
                continue

            usage = int(usage_str)

            if mount == "/mnt/backup" and usage > 98:
                log(f"FAIL: Filesystem {mount} is over threshold: {usage}%")
                failures = True
            elif mount != "/mnt/backup" and usage > 85:
                log(f"FAIL: Filesystem {mount} is over threshold: {usage}%")
                failures = True
        except Exception as e:
            log(f"WARNING: Error processing filesystem line '{line}': {e}")

    if not failures:
        log("PASS: All filesystems within threshold limits.")

def check_inode_usage():
    section("Inode Usage")
    log("Desired state: All filesystems ≤ 85% inode usage")
    df_output = run_command_to_output("df -ih", shell=True)

    for line in df_output.split('\n')[1:]:  # Skip header line
        parts = line.split()
        if not parts:
            continue

        try:
            usage = parts[-2].rstrip('%')
            mount = parts[-1]

            if not usage or not usage.isdigit() or mount == "Mounted":
                continue

            usage = int(usage)
            if usage > 85:
                log(f"FAIL: Inode usage for {mount} is {usage}%")
        except:
            continue

# -------------------
# Package & Update Compliance
# -------------------

def check_security_updates():
    section("Security Updates Check")
    log("Desired state: No available security updates")
    sec_updates = run_command("dnf updateinfo list security | grep -c '^SEC'", shell=True)
    log(f"Security updates available: {sec_updates}")
    if sec_updates == "0":
        log("PASS: No security updates pending.")
    else:
        log("FAIL: Security updates available.")

def check_orphaned_packages():
    section("Orphaned Packages")
    log("Desired state: Only veeamdeployment and veeamtransport allowed")
    extras_output = run_command("dnf repoquery --extras -q", shell=True)

    # Handle empty or error output
    if extras_output.startswith("Error") or extras_output.startswith("Command failed"):
        log("WARNING: Could not check orphaned packages")
        return

    # Split by lines and filter empty strings
    extras = [pkg for pkg in extras_output.split('\n') if pkg.strip()]

    if not extras:
        log("PASS: No orphaned packages found.")
        return

    unauthorized = []
    for pkg in extras:
        if pkg.strip() and pkg not in ["veeamdeployment", "veeamtransport"]:
            unauthorized.append(pkg)
            log(f"FAIL: Unexpected orphaned package found: {pkg}")

    if not unauthorized:
        log("PASS: No unauthorized orphaned packages.")

# -------------------
# Networking
# -------------------

def check_firewalld_status():
    section("Firewalld Status")
    log("Desired state: firewalld is active")
    firewalld = run_command(["systemctl", "is-active", "firewalld"])
    log(f"Current state: {firewalld}")
    if firewalld == "active":
        log("PASS: firewalld is active.")
    else:
        log("FAIL: firewalld is not active.")

def check_listening_ports():
    section("Listening Ports")
    log("Info only")
    run_command_to_output(["ss", "-tulpn"])

def check_ntp_synchronization():
    section("NTP Synchronization")
    log("Desired state: System clock synchronized: yes")
    timedatectl = run_command(["timedatectl", "status"])

    # Check if command was successful
    if timedatectl.startswith("Error") or timedatectl.startswith("Command failed"):
        log("WARNING: Could not check NTP synchronization")
        log("FAIL: Unable to determine clock synchronization status")
        return

    synced = "unknown"
    for line in timedatectl.split('\n'):
        if "System clock synchronized" in line:
            parts = line.split()
            if len(parts) >= 4:
                synced = parts[-1]
            break

    log(f"System clock synchronized: {synced}")
    if synced.lower() == "yes":
        log("PASS: System clock is synchronized.")
    else:
        log("FAIL: System clock is not synchronized.")

def check_network_interface_stats():
    section("Network Interface Statistics")
    log("Info only")
    run_command_to_output(["ip", "-s", "link"])

def check_ethernet_tool_stats():
    section("Ethernet Tool Statistics")
    log("Info only")
    primary_if = run_command("ip -o -4 route show to default | awk '{print $5}'", shell=True)
    if primary_if:
        run_command_to_output(["ethtool", "-S", primary_if])

# -------------------
# iSCSI Diagnostics (Info-only)
# -------------------

def check_iscsi_sessions():
    section("iSCSI Sessions")
    log("Info only")
    run_command_to_output(["iscsiadm", "-m", "session"])

def check_lsscsi_output():
    section("lsscsi Output")
    log("Info only")
    run_command_to_output(["lsscsi", "-t"])

def check_dmesg_iscsi_logs():
    section("dmesg iSCSI Logs")
    log("Info only")
    run_command_to_output("dmesg | grep -i iscsi", shell=True)

def check_journalctl_iscsi_logs():
    section("journalctl iSCSI Logs")
    if not check_command_exists("journalctl"):
        log("❌ journalctl command not found")
        return
    log("Info only")

    try:
        # Split the complex command into simpler steps to avoid shell=True
        # First get the kernel logs
        journalctl_output = run_command(["journalctl", "-b", "-k", "--no-pager"])

        # Then filter for relevant entries
        # Use Python's regex module instead of piping to grep
        import re
        pattern = re.compile(r'iscsi|reset|conn error', re.IGNORECASE)

        # Filter and log the results
        filtered_lines = []
        for line in journalctl_output.splitlines():
            if pattern.search(line):
                filtered_lines.append(line)

        if filtered_lines:
            log("\n".join(filtered_lines))
        else:
            log("No iSCSI related logs found")

    except Exception as e:
        log(f"❌ Error checking journalctl logs: {str(e)}")

# -------------------
# Helper functions
# -------------------

def check_command_exists(command):
    """Check if a command exists in the system"""
    try:
        subprocess.run(["which", command], capture_output=True, text=True, check=False)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

# -------------------
# Main function
# -------------------

def main():
    # Initial banner
    script_name = os.path.basename(__file__)
    log(f"Rocky Linux Health Check - {script_name}")

    # Use safer alternatives to subprocess.check_output
    try:
        # Get current date
        date_result = run_command(["date"])
        log(f"Started at: {date_result}")

        # Get current user
        user_result = run_command(["whoami"])
        log(f"Running as user: {user_result}")
    except Exception as e:
        log(f"Error during initialization: {str(e)}")

    log("")

    # Security & Access Controls
    check_selinux()
    check_ssh_service()
    check_ssh_root_login()
    check_wheel_group()
    check_login_shell_users()
    check_sudoers_permissions()

    # System State & Health
    check_system_uptime()
    check_system_load()
    check_memory_usage()
    check_zombie_processes()
    check_failed_services()

    # Storage & Filesystem
    check_filesystem_usage()
    check_inode_usage()

    # Package & Update Compliance
    check_security_updates()
    check_orphaned_packages()

    # Networking
    check_firewalld_status()
    check_listening_ports()
    check_ntp_synchronization()
    check_network_interface_stats()
    check_ethernet_tool_stats()

    # iSCSI Diagnostics
    check_iscsi_sessions()
    check_lsscsi_output()
    check_dmesg_iscsi_logs()
    check_journalctl_iscsi_logs()

    # Final
    section("Health Check Complete")
    log(f"✅ Health check saved to: {OUTPUT}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nScript interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        log(f"\nCritical error: {str(e)}")
        sys.exit(2)
