# Linux Server Security Audit and Hardening Script

## 📌 Overview

This Bash script automates the process of security auditing and hardening for Linux servers. It is reusable and modular, allowing easy deployment across multiple servers to ensure they meet stringent security standards. The script includes checks for common security vulnerabilities, IP configurations, public vs. private IP identification, and hardening measures.

### Features:
- User and group audits
- File and directory permission checks
- Service audits
- Firewall and network security checks
- IP and network configuration checks (public vs. private IP identification)
- Security updates and patching checks
- Log monitoring for suspicious activity
- SSH configuration hardening
- IPv6 disabling (if not needed)
- Bootloader protection (GRUB password setup)
- Custom security checks based on organizational policies
- Automated security updates configuration
- Email alerts and notifications (optional)

---

## ⚡ Installation

Follow these steps to install and run the Security Audit and Hardening Script on your Linux server:

``
# Step 1: Clone the repository
git clone https://github.com/Nachiketvc/-Script-for-Automating-Security-Audits-and-Server-Hardening-on-Linux-Servers-.git

# Step 2: Navigate to the project directory
cd security-audit-hardening-script

# Step 3: Give execution permission to the script
chmod +x security_audit_hardening.sh

# Step 4: Run the script with sudo
sudo ./security_audit_hardening.sh


## Prerequisites and Instructions

Before running the script, make sure you have the following prerequisites installed and configurations set up:

### 1. **Service Audit Option**
- Ensure that `sshd` and `iptables` are installed on your system for the service audit checks.

### 2. **Security Updates and Patching**
- Please note that automatic updates have **not** been enabled for security updates and patching in this script. You'll need to manage updates manually or configure them as per your requirements.

### 3. **Log Monitoring**
- The script will save a log file on your system that contains the audit details and security checks. This log file will help you review and take necessary actions based on the results.






