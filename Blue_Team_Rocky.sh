#!/bin/bash

# Redirecting all output to corresponding log files
exec > >(tee -a script_output.log) 2>&1

# Function to pause and clear screen
pause_and_clear() {
    read -p "Press [Enter] to continue..."
    clear
}

# Function to update and upgrade the system
update_system() {
    echo "Updating and upgrading system..."
    sudo dnf update -y
    echo "System updated and upgraded"
    pause_and_clear
}

# Function to manage user accounts and permissions
manage_users() {
    local user_list=$1
    local essential_users=("root" "bin" "daemon" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-timesync" "systemd-network" "systemd-resolve" "systemd-bus-proxy")

    echo "Reading user list from $user_list..."

    # Check users from the provided user list
    while read -r user; do
        echo "Checking user: $user"
        if ! id "$user" &>/dev/null; then
            echo "User $user does not exist, skipping..."
        fi
    done < "$user_list"

    # Identify unauthorized users not in the provided user list
    echo "Identifying unauthorized users..."
    > unauthorized_users.txt
    for user in $(cut -d: -f1 /etc/passwd); do
        if ! grep -q "^$user$" "$user_list" && [[ ! " ${essential_users[@]} " =~ " $user " ]]; then
            echo "Identified unauthorized user: $user"
            echo "$user" >> unauthorized_users.txt
        fi
    done

    pause_and_clear
}

# Function to audit admin accounts and review user permissions
audit_admin_accounts() {
    echo "Auditing admin accounts and user permissions..."
    awk -F':' '$3 == 0 {print $1}' /etc/passwd
    getent passwd | awk -F: '{print $1}' | xargs -I {} sudo -l -U {}
    pause_and_clear
}

# Function to enforce password policies
enforce_password_policies() {
    echo "Enforcing password policies..."
    echo "password requisite pam_pwquality.so retry=3 minlen=15 dcredit=-1 ucredit=-1 lcredit=-1" | sudo tee -a /etc/pam.d/common-password
    sudo chage --maxdays 90 newuser
    echo "Password policies enforced"
    pause_and_clear
}

# Function to lock accounts after failed attempts
lock_accounts_after_failed_attempts() {
    echo "Locking accounts after failed attempts..."
    echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=1800" | sudo tee -a /etc/pam.d/common-auth
    echo "Accounts will be locked after 5 failed attempts"
    pause_and_clear
}

# Function to ensure IPv4 is enabled and IPv6 is disabled
configure_ipv4_ipv6() {
    echo "Ensuring IPv4 is enabled..."
    if sysctl net.ipv4.ip_forward | grep "net.ipv4.ip_forward = 0"; then
        sudo sysctl -w net.ipv4.ip_forward=1
    fi
    echo "Disabling IPv6..."
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
    pause_and_clear
}

# Function to enable and configure UFW (firewall)
configure_ufw() {
    echo "Enabling and configuring UFW..."
    sudo dnf install -y ufw
    sudo ufw enable
    sudo ufw allow ssh
    sudo ufw default deny
    echo "UFW firewall configured"
    pause_and_clear
}

# Function to check open ports and running services
check_open_ports() {
    echo "Checking open ports and services..."
    sudo netstat -tulnp
    pause_and_clear
}

# Function to secure remote access (SSH)
secure_remote_access() {
    echo "Securing remote access (SSH)..."
    sudo sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config || { echo "Error modifying SSH config for Port"; exit 1; }
    sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config || { echo "Error modifying SSH config for PermitRootLogin"; exit 1; }
    sudo systemctl restart sshd || { echo "Error restarting SSH service"; exit 1; }
    echo "Remote access secured"
    pause_and_clear
}

# Function to create secure configuration baselines with Lynis
secure_baselines() {
    echo "Creating secure configuration baselines..."
    sudo dnf install -y lynis
    sudo lynis audit system
    pause_and_clear
}

# Function to install and configure ClamAV
install_clamav() {
    echo "Installing and configuring ClamAV..."
    sudo dnf install -y clamav
    sudo freshclam
    sudo clamscan -r /home
    pause_and_clear
}

# Function to check and remove malicious files
check_malicious_files() {
    echo "Checking for malicious files..."
    sudo clamscan -r --remove /home
    echo "Malicious files checked and removed"
    pause_and_clear
}

# Function to check Bash history for all users
check_bash_history() {
    echo "Checking Bash history for all users..."
    for user in $(cut -d: -f1 /etc/passwd); do
        home_dir=$(eval echo ~$user)
        if [ -f "$home_dir/.bash_history" ]; then
            echo "Bash history for $user:"
            cat "$home_dir/.bash_history"
        fi
    done
    pause_and_clear
}

# Main execution
if [ $# -lt 1 ]; then
    echo "Usage: $0 <user_list.txt>"
    exit 1
fi

# Get the user list from the command-line argument
user_list=$1

# Execute the functions in a logical order
update_system
manage_users "$user_list"
audit_admin_accounts
enforce_password_policies
lock_accounts_after_failed_attempts
configure_ipv4_ipv6
configure_ufw
check_open_ports
secure_remote_access
secure_baselines
install_clamav
check_malicious_files
check_bash_history

echo "All Blue Team tasks and configurations completed."
