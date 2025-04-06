#!/bin/bash

#=========================================
#     LINUX USER & FILE AUDIT TOOL
#=========================================

#========== CODE 1 - USER & GROUP AUDIT ==========

list_users() {
    echo "-----------------------------------------"
    echo "NORMAL USERS (UID >= 1000)"
    echo "-----------------------------------------"
    awk -F: '$3 >= 1000 && $1 != "nobody" { print $1 }' /etc/passwd
}

list_groups() {
    echo "-----------------------------------------"
    echo "NORMAL GROUPS (GID >= 1000)"
    echo "-----------------------------------------"
    awk -F: '$3 >= 1000 && $1 != "nobody" { print $1 }' /etc/group
}

check_uid_zero_users() {
    echo "-----------------------------------------"
    echo "USERS WITH UID 0 (ROOT PRIVILEGES)"
    echo "-----------------------------------------"
    awk -F: '($3 == 0) {print $1}' /etc/passwd
}

check_user_passwords() {
    echo "-----------------------------------------"
    echo "USERS WITHOUT PASSWORDS / LOCKED ACCOUNTS"
    echo "-----------------------------------------"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | while read user; do
        passwd_status=$(sudo passwd -S "$user" 2>/dev/null)
        if [[ "$passwd_status" == *"NP"* ]]; then
            echo "$user: NO PASSWORD SET"
        elif [[ "$passwd_status" == *"LK"* ]]; then
            echo "$user: ACCOUNT LOCKED"
        else
            echo "$user: Password Set"
        fi
    done
}

run_user_group_audit() {
    list_users
    list_groups
    check_uid_zero_users
    check_user_passwords
}

#========== CODE 2 - FILE PERMISSION AUDIT ==========

get_human_users() {
    awk -F: '$3 >= 1000 && $3 < 65534 { print $1 ":" $6 }' /etc/passwd
}

check_user_world_writable() {
    echo "---------------------------------------------"
    echo "🔍 Checking World-Writable Files/Dirs (User Only)"
    echo "---------------------------------------------"

    while IFS=: read -r user home_dir; do
        if [ -d "$home_dir" ]; then
            echo "User: $user"
            find "$home_dir" -xdev -type f -perm -0002 -ls 2>/dev/null
            find "$home_dir" -xdev -type d -perm -0002 -ls 2>/dev/null
        fi
    done < <(get_human_users)
}

check_user_ssh_permissions() {
    echo -e "\n---------------------------------------------"
    echo "🔐 Checking .ssh Permissions for Users"
    echo "---------------------------------------------"
   while IFS=: read -r user home_dir; do
        ssh_dir="$home_dir/.ssh"
        if [ -d "$ssh_dir" ]; then
            echo "User: $user"
            dir_perms=$(stat -c "%a" "$ssh_dir")
            [[ "$dir_perms" != "700" ]] && echo "  ⚠️  $ssh_dir should be 700 (found $dir_perms)" || echo "  ✅ $ssh_dir permissions are OK"

            auth_file="$ssh_dir/authorized_keys"
            if [ -f "$auth_file" ]; then
                file_perms=$(stat -c "%a" "$auth_file")
                [[ "$file_perms" != "600" ]] && echo "  ⚠️  $auth_file should be 600 (found $file_perms)" || echo "  ✅ $auth_file permissions are OK"
            fi
        fi
    done < <(get_human_users)
}

check_user_suid_sgid() {
    echo -e "\n---------------------------------------------"
    echo "⚙️  Checking SUID/SGID Files (User-Owned)"
    echo "---------------------------------------------"

    while IFS=: read -r user home_dir; do
        uid=$(id -u "$user" 2>/dev/null)
        if [ -n "$uid" ]; then
            echo "User: $user (UID: $uid)"
            find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -uid "$uid" -exec ls -l {} \; 2>/dev/null
        fi
    done < <(get_human_users)
}

run_file_permission_audit() {
    check_user_world_writable
    check_user_ssh_permissions
    check_user_suid_sgid
}


#========== CODE 3 - SERVICE AUDIT ==========


check_services() {
    echo "=============================================="
    echo "            🔧 SERVICE AUDIT REPORT           "
    echo "=============================================="

    echo -e "\n📋 ALL RUNNING SERVICES"
    echo "----------------------------------------------"
    systemctl list-units --type=service --state=running 2>/dev/null || echo "systemctl not supported or access denied."

    echo -e "\n🔐 CRITICAL SERVICES STATUS (sshd, iptables)"
    echo "----------------------------------------------"
    critical_services=("sshd" "iptables" "firewalld")  # Add or remove as needed
    for svc in "${critical_services[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "✔️  $svc is running"
        else
            echo "❌ $svc is NOT running"
        fi
    done

    echo -e "\n🚫 UNNECESSARY OR SUSPICIOUS SERVICES CHECK"
    echo "----------------------------------------------"
    suspicious_services=("telnet" "ftp" "rsh" "rexec" "xinetd")
    for svc in "${suspicious_services[@]}"; do
        if systemctl list-units --type=service 2>/dev/null | grep -qw "$svc"; then
            echo "⚠️  $svc is running (Consider disabling)"
        else
            echo "✅ $svc is not running"
        fi
    done

    echo -e "\n🔍 SERVICES LISTENING ON PORTS"
    echo "----------------------------------------------"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn | grep LISTEN || echo "No services are currently listening."
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn | grep LISTEN || echo "No services are currently listening."
   else
        echo "Neither ss nor netstat is available."
    fi

    echo
}

#========== CODE 4 - FIREWALL AND NETWORK SECURITY ==========


check_firewall_network_security() {
    echo "=============================================="
    echo "  🔥 FIREWALL & NETWORK SECURITY AUDIT REPORT  "
    echo "=============================================="

    echo -e "\n🛡️  1. FIREWALL STATUS & RULE VERIFICATION"
    echo "----------------------------------------------"
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(sudo ufw status | grep -i "status")
        echo "UFW Status: $ufw_status"
        if [[ "$ufw_status" == *"inactive"* ]]; then
            echo "❌ UFW is not active! Please enable it for security."
        else
            echo "✅ UFW is active."
            sudo ufw status verbose
        fi
    elif command -v iptables >/dev/null 2>&1; then
        iptables_rules=$(sudo iptables -L -n)
        if [[ -z "$iptables_rules" ]]; then
            echo "❌ iptables is installed but has no active rules!"
        else
            echo "✅ iptables is active and has rules:"
            echo "$iptables_rules"
        fi
    else
        echo "❌ Neither UFW nor iptables is installed."
    fi

    echo -e "\n📡 2. OPEN PORTS & ASSOCIATED SERVICES"
 echo "----------------------------------------------"
    if command -v ss >/dev/null 2>&1; then
        echo "Using ss to list open ports..."
        ss -tulpn | grep LISTEN || echo "✅ No open ports detected."
    elif command -v netstat >/dev/null 2>&1; then
        echo "Using netstat to list open ports..."
        netstat -tulpn | grep LISTEN || echo "✅ No open ports detected."
    else
        echo "❌ Neither ss nor netstat is available."
    fi

    echo -e "\n🔁 3. IP FORWARDING CHECK"
    echo "----------------------------------------------"
    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ "$ip_forward" -eq 1 ]; then
        echo "⚠️ IP forwarding is ENABLED (System may be forwarding packets)."
    else
        echo "✅ IP forwarding is DISABLED (Secure by default)."
    fi

    echo
}


#========== CODE 5 - IP AND NETWORK CONFIGURATION ==========


ip_network_config_check() {
    echo "4. IP AND NETWORK CONFIGURATION CHECKS"
    echo "----------------------------------------------"

    public_ips=()
    private_ips=()
    all_ips=()

    echo "Assigned IP Addresses:"
    while read ip; do
        all_ips+=("$ip")
        if [[ "$ip" =~ ^10\. || "$ip" =~ ^192\.168\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            private_ips+=("$ip")
            echo "Private IP: $ip"
        else
            public_ips+=("$ip")
            echo "Public IP:  $ip"
        fi
    done < <(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

    echo
    echo "IP Address Summary:"
    echo "Total IPs Assigned: ${#all_ips[@]}"
    echo "Public IPs: ${#public_ips[@]}"
    echo "Private IPs: ${#private_ips[@]}"

    echo
    echo "Checking if SSH is exposed on public IPs..."
    if [ ${#public_ips[@]} -eq 0 ]; then
        echo "No public IPs detected. SSH exposure risk is low."
else
        for ip in "${public_ips[@]}"; do
            ssh_exposed=$(sudo ss -tuln | grep ":22" | grep "$ip")
            if [ -n "$ssh_exposed" ]; then
                echo "Warning: SSH is exposed on public IP $ip"
            else
                echo "SSH is not exposed on public IP $ip"
            fi
        done
    fi
}


#========== CODE 6 - SECURITY UPDATE AND PATCHING ==========

security_updates_check() {
    echo "5. SECURITY UPDATES AND PATCHING"
    echo "----------------------------------------------"

    if command -v apt &> /dev/null; then
        echo "Checking for security updates (APT-based system)..."
        sudo apt update -qq > /dev/null
        available_updates=$(apt list --upgradable 2>/dev/null | grep -i security)
        if [ -n "$available_updates" ]; then
            echo "Security updates available:"
            echo "$available_updates"
        else
            echo "No security updates available."
        fi

        echo
        echo "Checking if unattended-upgrades is enabled..."
        if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
            cat /etc/apt/apt.conf.d/20auto-upgrades
        else
            echo "Unattended upgrades not configured."
        fi

    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        echo "Checking for security updates (YUM/DNF-based system)..."
      if command -v dnf &> /dev/null; then
            sudo dnf check-update --security
        else
            sudo yum --security check-update
        fi

        echo
        echo "Checking for automatic security update service..."
        if systemctl is-enabled yum-cron &>/dev/null || systemctl is-enabled dnf-automatic &>/dev/null; then
            echo "Automatic security update service is enabled."
        else
            echo "Automatic security update service is NOT enabled."
        fi
    else
        echo "Unsupported package manager. Cannot check for updates."
    fi
}


#========== CODE 7 - LOG MONITORING ==========

log_monitoring_check() {
    echo "6. LOG MONITORING"
    echo "----------------------------------------------"

    echo "Checking for recent suspicious log entries (e.g., failed SSH login attempts)..."

    output_file="ssh_failed_logins_report.txt"
    > "$output_file"  # clear the file before appending

    if command -v journalctl &> /dev/null; then
        echo "Using journalctl to check SSH failed logins (last 24 hours)..." | tee -a "$output_file"
        journalctl -u ssh --since "24 hours ago" | grep -i "failed password" | tee -a "$output_file" | awk '{print $1, $2, $3, $11, $13}' | sort | uniq -c | sort -nr | tee -a "$output_file"

    elif [ -f /var/log/auth.log ]; then
        echo "Using /var/log/auth.log to check failed logins (last 24 hours)..." | tee -a "$output_file"
        grep "Failed password" /var/log/auth.log | tee -a "$output_file" | awk '{print $1, $2, $3, $11, $13}' | sort | uniq -c | sort -nr | tee -a "$output_file"
          elif [ -f /var/log/secure ]; then
        echo "Using /var/log/secure to check failed logins (last 24 hours)..." | tee -a "$output_file"
        grep "Failed password" /var/log/secure | tee -a "$output_file" | awk '{print $1, $2, $3, $11, $13}' | sort | uniq -c | sort -nr | tee -a "$output_file"

    else
        echo "No suitable log files found for checking SSH failed logins." | tee -a "$output_file"
    fi

    echo | tee -a "$output_file"
    echo "Login attempts saved to: $output_file"
    echo
}


#========== CODE 8 - HARDEN LINUX SECURITY ==========

harden_linux_security() {
    echo "🔐 Starting Linux security hardening..."

    # ========== SSH CONFIGURATION ==========
    echo -e "\n🛠️ Configuring SSH..."
    SSH_CONFIG="/etc/ssh/sshd_config"
    [ -f "$SSH_CONFIG" ] && sudo cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"

    sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG"

    echo "🔄 Restarting SSH service..."
    if sudo systemctl restart sshd; then
        echo "✅ SSH service restarted successfully."
    else
        echo "❌ Failed to restart SSH."
    fi
    echo "ℹ️ SSH now disables root login & password login. Ensure key-based authentication is set up!"

    echo -e "\n🔍 Checking for existing SSH keys..."
    if [ -f ~/.ssh/authorized_keys ]; then
        chmod 600 ~/.ssh/authorized_keys
        echo "✅ ~/.ssh/authorized_keys exists and permissions set."
    else
        echo "❌ No SSH key found. Use ssh-keygen + ssh-copy-id to set one."
    fi

    [ -f ~/.ssh/id_rsa ] && chmod 600 ~/.ssh/id_rsa && echo "✅ id_rsa permissions set."

    # ========== GRUB PASSWORD CONFIGURATION ==========
    echo -e "\n🔐 Securing GRUB with password..."
    read -s -p "Enter GRUB password: " grub_pass
    echo
    read -s -p "Confirm GRUB password: " grub_pass_confirm
    echo

    if [ "$grub_pass" != "$grub_pass_confirm" ]; then
        echo "❌ Passwords do not match. Exiting."
        return 1
    fi

    echo "🔑 Generating GRUB password hash..."
    grub_hash=$(echo -e "$grub_pass\n$grub_pass" | grub-mkpasswd-pbkdf2 2>/dev/null | grep 'grub.pbkdf2' | awk '{print $7}')
    if [ -z "$grub_hash" ]; then
        echo "❌ Failed to generate GRUB hash."
        return 1
    fi

    custom_file="/etc/grub.d/40_custom"
    sudo cp "$custom_file" "${custom_file}.bak"
    sudo tee "$custom_file" > /dev/null <<EOF
set superuser="admin"
password_pbkdf2 admin $grub_hash
EOF

    echo "🔄 Updating GRUB config..."
    sudo grub-mkconfig -o /boot/grub/grub.cfg && echo "✅ GRUB is password protected. Reboot to take effect."
    echo "ℹ️ GRUB User: admin"

    # ========== FIREWALL CONFIGURATION ==========
    echo -e "\n🔥 Setting up iptables firewall rules..."
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t mangle -F

    echo "🔐 Setting default policies..."
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT ACCEPT

    echo "✅ Allowing loopback, SSH, web traffic, and established connections..."
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    sudo iptables -A INPUT -j DROP

    echo "💾 Saving iptables rules..."
    sudo iptables-save > /etc/iptables.rules

    if [ -f /etc/rc.local ]; then
        sudo grep -q "iptables-restore" /etc/rc.local || echo "iptables-restore < /etc/iptables.rules" | sudo tee -a /etc/rc.local
    elif [ -d /etc/network/if-pre-up.d ]; then
        sudo tee /etc/network/if-pre-up.d/iptables > /dev/null <<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
        sudo chmod +x /etc/network/if-pre-up.d/iptables
        echo "✅ Firewall rules will persist across reboots."
    fi

    # ========== AUTOMATIC UPDATES ==========
    echo -e "\n⚙️ Enabling unattended security updates..."
    sudo apt update
    sudo apt install -y unattended-upgrades apt-config-auto-update

    sudo dpkg-reconfigure -f noninteractive unattended-upgrades

    echo "🛠️ Configuring auto-remove and reboot policies..."
    sudo tee /etc/apt/apt.conf.d/99autoremove-old > /dev/null <<EOF
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Keep-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::Unused-Dependencies::MaxAge "120";
EOF

    sudo systemctl restart unattended-upgrades

    echo -e "\n✅ Linux hardening completed."
    echo "🚀 Summary: SSH locked down, GRUB secured, firewall enforced, automatic updates enabled."
}


#========== CODE 9 - CUSTOM SCRIPT ============

run_custom_checks() {
    SCRIPT_DIR="$(dirname "$(realpath "$0")")"
    CUSTOM_CHECKS="$SCRIPT_DIR/custom_checks.sh"

    echo "🔍 Looking for custom checks at: $CUSTOM_CHECKS" | tee -a "$report_file"

    if [ -f "$CUSTOM_CHECKS" ]; then
        echo "🚀 Running custom security checks..." | tee -a "$report_file"
        
        # 🔥 Run the custom script and log output
        bash "$CUSTOM_CHECKS" >> "$report_file" 2>&1
        
        echo "✅ Custom checks finished and output logged." | tee -a "$report_file"
        echo "📄 Custom script executed successfully and results added to report." | tee -a "$report_file"
    else
        echo "⚠️ No custom checks file found at $CUSTOM_CHECKS" | tee -a "$report_file"
    fi
}



#========== CODE 10 - REPORT ==========

summary_audit_report() {
    echo "📋 Running Security Summary Audit..."

    LOG_DIR="$HOME/security_audit_logs"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$LOG_DIR"

    for user in $(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}'); do
        home_dir=$(eval echo "~$user")
        report_file="$LOG_DIR/audit_${user}_${TIMESTAMP}.log"
        issues_found=0

        {
            echo "========= SECURITY SUMMARY REPORT for $user ========="
            echo "Date: $(date)"
            echo "Hostname: $(hostname)"
            echo

            echo "🔐 Password status:"
            if sudo passwd -S "$user" 2>/dev/null | grep -q "NP"; then
                echo "❌ $user has NO PASSWORD!"
                issues_found=1
            else
                echo "✅ $user has a password"
            fi
            echo

            echo "🛡️ .ssh permission check:"
            ssh_dir="$home_dir/.ssh"
            if [ -d "$ssh_dir" ]; then
                perms=$(stat -c "%a" "$ssh_dir")
                echo "$ssh_dir found with permissions: $perms"
                if [[ "$perms" -gt 700 ]]; then
                    echo "⚠️ Permissions too open"
                    issues_found=1
                fi
            else
                echo "❌ No .ssh directory for $user"
                issues_found=1
            fi
            echo

            echo "🔧 sshd & firewall service check:"
            if systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
                echo "✅ SSH service is running"
            else
                echo "❌ SSH service is not running"
                issues_found=1
            fi

            if systemctl is-active ufw >/dev/null 2>&1; then
                echo "✅ UFW firewall is running"
            elif systemctl is-active iptables >/dev/null 2>&1; then
                echo "✅ iptables firewall is running"
            else
                echo "❌ No firewall (iptables or ufw) is running"
                issues_found=1
            fi
            echo

            echo "🌐 IP forwarding:"
            if [ "$(sysctl -n net.ipv4.ip_forward)" -eq 1 ]; then
                echo "⚠️ IP forwarding is ENABLED"
                issues_found=1
            else
                echo "✅ IP forwarding is disabled"
            fi
            echo

            echo "🚨 Failed SSH login attempts:"
            if [ -f /var/log/auth.log ]; then
                fails=$(grep "Failed password" /var/log/auth.log | grep "$user" | tail -n 5)
                if [ -n "$fails" ]; then
                    echo "$fails"
                    issues_found=1
                else
                    echo "✅ No failed login attempts for $user"
                fi
            else
                echo "⚠️ Log file /var/log/auth.log not found!"
            fi
        } > "$report_file"

        echo "✅ Report saved: $report_file"

        if [ "$issues_found" -eq 1 ]; then
            mail -s "⚠️ Security Issue Detected for $user" root < "$report_file"
            echo "📧 Alert sent to root for $user"
        else
            echo "✅ No issues for $user. No mail sent."
            rm -f "$report_file"
        fi
    done
}






#========== MAIN MENU ==========

show_main_menu() {
    echo "=============================================="
    echo "         LINUX USER & FILE AUDIT TOOL         "
    echo "=============================================="
    echo "1. User & Group Audit"
    echo "2. User-Centric File Permission Audit"
    echo "3. Service Audit"
    echo "4. Firewall and Network Security"
    echo "5. IP and Network Configuration Checks"
    echo "6. Security and Update Checks"
    echo "7. Log Monitoring"
    echo "8. Server Hardning"
    echo "9. Custom Script"
    echo "9. Audit Summary"
    echo "0. Exit"
    echo "=============================================="
    read -p "Enter your choice [0-3]: " choice
}

#========== MAIN LOOP ==========

while true; do
    show_main_menu
    case $choice in
 1) run_user_group_audit ;;
        2) run_file_permission_audit ;;
        3) check_services ;;
        4) check_firewall_network_security;;
        5) ip_network_config_check;;
        6) security_updates_check;;
        7) log_monitoring_check;;
        8) harden_linux_security;;
        9) run_custom_checks;;
        10) summary_audit_report;;
        0) echo "Exiting..."; break ;;
        *) echo "Invalid choice. Please try again." ;;
    esac
    echo -e "\nPress Enter to continue..."
    read
done