# 🛡️ Linux Server Security Audit & Hardening Script

A **modular and reusable Bash script** to automate **security auditing and hardening** of Linux servers. Designed for quick deployment across multiple machines to ensure consistent security compliance.

---

## 🚀 Features

- ✅ **User & Group Audits**  
- 🔐 **File & Directory Permission Checks**  
- 🛠️ **Service Audits** (e.g., `sshd`, `iptables`)  
- 🔥 **Firewall & Network Security Checks**  
- 🌐 **Public vs. Private IP Identification**  
- 🧩 **Network Configuration Audits**  
- 🩹 **Security Updates & Patching Checks**  
- 📜 **Log Monitoring for Suspicious Activity**  
- 🔒 **SSH Configuration Hardening**  
- 🚫 **IPv6 Disabling** (if unnecessary)  
- 🧷 **GRUB Bootloader Protection**  
- ⚙️ **Custom Security Checks** (per org policies)  
- 📬 **Optional Email Alerts & Notifications**  
- ♻️ **Automated Security Updates Configuration**  

---

## 📦 Installation

Clone the repository and run the script with elevated privileges:

```bash```
## Step 1: Clone the repository
git clone https://github.com/Nachiketvc/-Script-for-Automating-Security-Audits-and-Server-Hardening-on-Linux-Servers-.git

'''bash```
## Step 2: Navigate into the project directory
cd security-audit-hardening-script

```bash```
## Step 3: Make the script executable
chmod +x security_audit_hardening.sh

```bash```
## Step 4: Run the script with sudo
sudo ./security_audit_hardening.sh

-------------------------------------------------------------------------------------------------------------------------------------------------


## ⚙️ Prerequisites
Before running the script, ensure the following:

## 🔍 1. Service Audit Requirements
Services like sshd and iptables should be installed on the target system.

## 🛡️ 2. Security Updates
Automatic security updates are not enabled by default.
You may choose to configure them manually or use the provided automation option.

## 📁 3. Log Monitoring
Audit results and security logs are saved locally.
