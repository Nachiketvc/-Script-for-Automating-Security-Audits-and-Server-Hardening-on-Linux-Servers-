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
- 🧷 **GRUB Bootloader Protection**  
- ⚙️ **Custom Security Checks** (per org policies)  
- 📬 **Email Alerts**  
- ♻️ **Automated Security Updates Configuration**


   **I have developed a Linux User Audit Script with an interactive, menu-based flow that enables users to select different audit tasks to run based on their input. The script is split into two main audit 
   sections:** 
   **Normal User (which checks for normal users, groups, root privileges, and password statuses) and User-Centric File Permission Audits (which checks for world-writable files, SSH directory 
   permissions, and SUID/SGID files).**

   **The script uses a switch-case structure to execute tasks based on the user's choice, providing a clear, organized method for running specific audits or all checks at once. The user-friendly interface ensures 
   ease of use and can be extended to add more functionality in the future.**

---

## 📦 Installation

Clone the repository and run the script with elevated privileges:


## Step 1: Clone the repository

git clone https://github.com/Nachiketvc/-Script-for-Automating-Security-Audits-and-Server-Hardening-on-Linux-Servers-.git

## Step 2: Navigate into the project directory
cd audit.sh
 
## Step 3: Make the script executable
chmod +x audit.sh

## Step 4: Run the script
./audit.sh

-------------------------------------------------------------------------------------------------------------------------------------------------


## ⚙️ Prerequisites 
• Before running the script, ensure the following:

## 🔍 1. Service Audit Requirements
• Services like sshd and iptables should be installed on the target system.

## 🛡️ 2. Security Updates
• Automatic security updates are not enabled by default. Just it will notify that updates are available.

## 📁 3. Log Monitoring
• Audit results and security logs are saved locally.

## 📁 4. Reporting and Alerting
• Here I have added root mail address. you can add your personal mail id too. 

## How to check mail.

• Login as a root user. (sudo su - )

• Make sure you have installed mail service. 

• use command - mail (you will get mail if there is any warning)

## 5. For Custom security checks.

• For custom security checks, make sure to create the file in the same directory where your main script is located.

## 6. For report

• A file would get dowloaded in your system.


--------------------------------------------------------------------------------------------------------------------------------------------------

