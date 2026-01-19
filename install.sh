#!/bin/bash

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

USERNAME=""
SSH_PORT=""
SSH_PUBLIC_KEY=""
SWAP_SIZE_GB=""
SUDO_CMD=""

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_error "Please run with: sudo $0 $*"
        exit 1
    fi
}

check_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS version"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        log_warn "This script is designed for Ubuntu. Proceeding anyway..."
    fi
}

update_system() {
    log_info "Stopping unattended-upgrades to avoid lock conflicts..."
    systemctl stop unattended-upgrades 2>/dev/null || true
    
    log_info "Updating system packages..."
    DEBIAN_FRONTEND=noninteractive apt update -qq
    
    log_info "Upgrading system packages (this may take a while)..."
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
    
    log_info "Waiting for any remaining package operations to complete..."
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        sleep 1
    done
    
    log_info "System packages updated"
    clear
}

show_help() {
    echo "VPN Server Setup"
    echo ""
    echo "Usage: $0"
    echo ""
    exit 0
}

show_header() {
    clear
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     VPN Server Setup                  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
}

prompt_user_input() {
    show_header
    
    while true; do
        read -p "Username: " USERNAME
        if [[ -z "$USERNAME" ]]; then
            echo -e "${RED}✗${NC} Username cannot be empty"
        elif [[ ! "$USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            echo -e "${RED}✗${NC} Invalid username format"
        else
            break
        fi
    done
    
    while true; do
        read -p "SSH Port (1-65535): " SSH_PORT
        if [[ -z "$SSH_PORT" ]]; then
            echo -e "${RED}✗${NC} SSH port cannot be empty"
            continue
        fi
        if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}✗${NC} Invalid port (must be a number)"
            continue
        fi
        if [[ "$SSH_PORT" -lt 1 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
            echo -e "${RED}✗${NC} Invalid port (must be 1-65535)"
            continue
        fi
        break
    done
    
    echo ""
    echo -e "${YELLOW}⚠${NC} Password authentication will be disabled"
    echo -e "${YELLOW}⚠${NC} SSH key is required for login"
    echo ""
    
    while true; do
        read -p "SSH Public Key: " SSH_PUBLIC_KEY
        if [[ -z "$SSH_PUBLIC_KEY" ]]; then
            echo -e "${RED}✗${NC} SSH key cannot be empty"
        elif [[ ! "$SSH_PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp|ssh-dss) ]]; then
            echo -e "${YELLOW}⚠${NC} Key format may be invalid"
            read -p "Continue anyway? (y/n): " continue_anyway
            if [[ "$continue_anyway" =~ ^[Yy]$ ]]; then
                break
            fi
        else
            break
        fi
    done
    
    while true; do
        read -p "Swap size in GB (0 to skip): " SWAP_SIZE_GB
        if [[ -z "$SWAP_SIZE_GB" ]]; then
            echo -e "${RED}✗${NC} Swap size cannot be empty"
            continue
        fi
        if ! [[ "$SWAP_SIZE_GB" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}✗${NC} Swap size must be a number"
            continue
        fi
        break
    done
    
    echo ""
    echo -e "${GREEN}✓${NC} Configuration:"
    echo -e "   ${GREEN}→${NC} Username: ${GREEN}$USERNAME${NC}"
    echo -e "   ${GREEN}→${NC} SSH Port: ${GREEN}$SSH_PORT${NC}"
    echo -e "   ${GREEN}→${NC} SSH Key: ${GREEN}${SSH_PUBLIC_KEY:0:40}...${NC}"
    echo -e "   ${GREEN}→${NC} Swap Size: ${GREEN}${SWAP_SIZE_GB}GB${NC}"
    echo ""
    read -p "Continue? (y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Installation cancelled${NC}"
        exit 0
    fi
    echo ""
}

update_sshd_config() {
    local key="$1"
    local value="$2"
    local config_file="$3"
    
    # Escape special characters in key and value for sed
    local escaped_key=$(printf '%s\n' "$key" | sed 's/[[\.*^$()+?{|]/\\&/g')
    local escaped_value=$(printf '%s\n' "$value" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Remove all existing lines with this key (commented or not)
    $SUDO_CMD sed -i "/^[[:space:]]*#*[[:space:]]*${escaped_key}[[:space:]]/d" "$config_file"
    
    # Add the new configuration at the end
    echo "${key} ${value}" | $SUDO_CMD tee -a "$config_file" > /dev/null
}

configure_ssh() {
    log_info "Configuring SSH..."
    
    local sshd_config="/etc/ssh/sshd_config"
    local sshd_config_backup="${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    local sshd_config_dir="/etc/ssh/sshd_config.d"
    local hardening_config="${sshd_config_dir}/99-hardening.conf"
    local hardening_config_backup="${hardening_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Backup main config
    $SUDO_CMD cp "$sshd_config" "$sshd_config_backup"
    log_info "SSH config backed up to: $sshd_config_backup"
    
    # Ensure sshd_config.d directory exists
    $SUDO_CMD mkdir -p "$sshd_config_dir"
    
    # Backup hardening config if exists
    if [[ -f "$hardening_config" ]]; then
        $SUDO_CMD cp "$hardening_config" "$hardening_config_backup"
        log_info "Hardening config backed up to: $hardening_config_backup"
    fi
    
    # Update port in main config
    update_sshd_config "Port" "$SSH_PORT" "$sshd_config"
    
    # Update AllowUsers in main config
    update_sshd_config "AllowUsers" "$USERNAME" "$sshd_config"
    
    # Create hardening config with highest priority (99)
    log_info "Creating SSH hardening configuration (99-hardening.conf)..."
    $SUDO_CMD tee "$hardening_config" > /dev/null <<EOF
# SSH Hardening Configuration
# Highest priority (99) - applied to all connections
# Created: $(date)

# Заблокировать пароль для всех пользователей
Match all
    PasswordAuthentication no
    PubkeyAuthentication yes
    ChallengeResponseAuthentication no
    PermitRootLogin no
    PermitEmptyPasswords no
    UsePAM no
EOF
    
    $SUDO_CMD chmod 644 "$hardening_config"
    log_info "SSH hardening configuration created at: $hardening_config"
    
    log_info "Validating SSH configuration syntax..."
    local syntax_check
    syntax_check=$(sshd -t 2>&1)
    local syntax_exit=$?
    
    if [[ $syntax_exit -ne 0 ]]; then
        log_error "SSH configuration syntax validation failed!"
        log_error "Syntax error: $syntax_check"
        log_error "Restoring backup configurations..."
        $SUDO_CMD cp "$sshd_config_backup" "$sshd_config"
        if [[ -f "$hardening_config_backup" ]]; then
            $SUDO_CMD cp "$hardening_config_backup" "$hardening_config"
        else
            $SUDO_CMD rm -f "$hardening_config"
        fi
        exit 1
    fi
    
    log_info "SSH configuration syntax is valid"
    
    log_info "Verifying SSH security settings..."
    local config_output
    config_output=$(sshd -T 2>&1)
    
    # Verify password authentication is disabled
    if echo "$config_output" | grep -qi "passwordauthentication yes"; then
        log_warn "Password authentication may still be enabled. Please verify manually."
    else
        log_info "✓ Password authentication is disabled"
    fi
    
    # Verify pubkey authentication is enabled
    if echo "$config_output" | grep -qi "pubkeyauthentication yes"; then
        log_info "✓ Pubkey authentication is enabled"
    else
        log_warn "Pubkey authentication may not be enabled. Please verify manually."
    fi
    
    # Verify root login is disabled
    if echo "$config_output" | grep -qi "permitrootlogin no"; then
        log_info "✓ Root login is disabled"
    else
        log_warn "Root login may still be enabled. Please verify manually."
    fi
    
    log_info "Restarting SSH service..."
    local ssh_service=""
    
    # Try to find SSH service - check both common names
    for service_name in sshd ssh; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -qE "^${service_name}\.service" || \
           systemctl is-enabled "$service_name" &>/dev/null || \
           systemctl status "$service_name" &>/dev/null; then
            ssh_service="$service_name"
            break
        fi
    done
    
    if [[ -z "$ssh_service" ]]; then
        log_error "SSH service (sshd or ssh) not found. Please restart manually."
        exit 1
    fi
    
    log_info "Found SSH service: $ssh_service"
    
    if systemctl is-active --quiet "$ssh_service" 2>/dev/null; then
        log_info "Restarting $ssh_service..."
        systemctl reload-or-restart "$ssh_service"
        sleep 2
        
        if systemctl is-active --quiet "$ssh_service" 2>/dev/null; then
            log_info "SSH service restarted successfully"
            
            if ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT "; then
                log_info "SSH is listening on port $SSH_PORT"
            else
                log_warn "SSH may not be listening on port $SSH_PORT yet. Please verify manually."
            fi
        else
            log_error "SSH service failed to restart!"
            log_error "Restoring backup configuration..."
            $SUDO_CMD cp "$sshd_config_backup" "$sshd_config"
            systemctl restart "$ssh_service" 2>/dev/null || true
            exit 1
        fi
    else
        log_warn "SSH service is not active. Starting it..."
        systemctl start "$ssh_service" 2>/dev/null || {
            log_error "Failed to start SSH service"
            exit 1
        }
        systemctl enable "$ssh_service" 2>/dev/null || true
        log_info "SSH service started and enabled"
    fi
    
    log_info "SSH configured successfully on port $SSH_PORT"
}

configure_fail2ban() {
    log_info "Configuring fail2ban..."
    
    if ! command -v fail2ban-server &> /dev/null; then
        log_info "Installing fail2ban..."
        PYTHONWARNINGS=ignore::SyntaxWarning DEBIAN_FRONTEND=noninteractive $SUDO_CMD apt install -y fail2ban 2>/dev/null || \
        DEBIAN_FRONTEND=noninteractive $SUDO_CMD apt install -y fail2ban 2>&1 | grep -v "SyntaxWarning" || true
    else
        log_info "fail2ban is already installed"
    fi
    
    local jail_local="/etc/fail2ban/jail.local"
    $SUDO_CMD tee "$jail_local" > /dev/null <<EOF
[DEFAULT]
bantime = 3600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
EOF
    
    $SUDO_CMD systemctl enable fail2ban
    $SUDO_CMD systemctl restart fail2ban
    
    log_info "fail2ban configured and started successfully"
}

configure_firewall() {
    log_info "Configuring UFW firewall..."
    
    if ! command -v ufw &> /dev/null; then
        log_info "Installing UFW..."
        DEBIAN_FRONTEND=noninteractive $SUDO_CMD apt install -y ufw
    fi
    
    log_info "Disabling UFW temporarily to configure rules..."
    $SUDO_CMD ufw --force disable
    
    log_info "Removing old SSH port 22 rule if exists..."
    $SUDO_CMD ufw delete allow 22/tcp 2>/dev/null || true
    
    if $SUDO_CMD ufw app list 2>/dev/null | grep -q "OpenSSH"; then
        log_info "OpenSSH profile found, updating port to $SSH_PORT..."
        local openssh_profile="/etc/ufw/applications.d/openssh-server"
        if [[ -f "$openssh_profile" ]]; then
            $SUDO_CMD sed -i "s/^ports=.*/ports=$SSH_PORT\/tcp/" "$openssh_profile"
            $SUDO_CMD ufw app update OpenSSH
            log_info "OpenSSH profile updated to port $SSH_PORT"
        fi
        $SUDO_CMD ufw allow OpenSSH
    else
        log_info "OpenSSH profile not found, adding port manually"
        $SUDO_CMD ufw allow "$SSH_PORT/tcp" comment 'SSH'
    fi
    
    local before_rules="/etc/ufw/before.rules"
    local before_rules_backup="${before_rules}.backup.$(date +%Y%m%d_%H%M%S)"
    
    $SUDO_CMD cp "$before_rules" "$before_rules_backup"
    log_info "UFW before.rules backed up to: $before_rules_backup"
    
    if $SUDO_CMD grep -q "# ok icmp codes for INPUT" "$before_rules"; then
        $SUDO_CMD sed -i '/# ok icmp codes for INPUT/a -A ufw-before-input -p icmp --icmp-type source-quench -j DROP' "$before_rules"
        $SUDO_CMD sed -i '/# ok icmp codes for INPUT/,/^$/{s/-j ACCEPT/-j DROP/g}' "$before_rules"
        $SUDO_CMD sed -i '/# ok icmp code for FORWARD/,/^$/{s/-j ACCEPT/-j DROP/g}' "$before_rules"
    else
        log_warn "Could not find ICMP sections in before.rules. Manual configuration may be needed."
    fi
    
    log_info "Enabling UFW firewall..."
    $SUDO_CMD ufw --force disable
    echo "y" | $SUDO_CMD ufw --force enable
    
    if $SUDO_CMD ufw status | grep -q "Status: active"; then
        log_info "Firewall configured and enabled successfully"
    else
        log_warn "Firewall may not be active. Please check manually."
    fi
}

create_user() {
    log_info "Setting up user management..."
    
    if id "$USERNAME" &>/dev/null; then
        log_warn "User $USERNAME already exists. Skipping user creation."
    else
        log_info "Creating user: $USERNAME"
        log_info "Please set a password for the new user:"
        useradd -m -s /bin/bash "$USERNAME"
        passwd "$USERNAME"
        log_info "User $USERNAME created with password"
    fi
    
    usermod -aG sudo "$USERNAME"
    log_info "User $USERNAME added to sudo group"
    
    local prompt_file="/etc/profile.d/custom_prompt.sh"
    
    if [[ ! -f "$prompt_file" ]]; then
        $SUDO_CMD tee "$prompt_file" > /dev/null <<'EOF'
# Custom prompt - show server IP address
if [[ -z "${SERVER_IP:-}" ]]; then
    SERVER_IP=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || \
                curl -s --max-time 3 ifconfig.co 2>/dev/null || \
                curl -s --max-time 3 icanhazip.com 2>/dev/null)
    if [[ -z "${SERVER_IP:-}" ]]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
    fi
    export SERVER_IP
fi

PS1="\u@$SERVER_IP\$ "
EOF

        $SUDO_CMD chmod +x "$prompt_file"
        log_info "Custom prompt configured globally (server IP address)"
    fi
    
    if [[ -f /root/.bashrc ]] && ! grep -q "custom_prompt.sh" /root/.bashrc; then
        echo "" >> /root/.bashrc
        echo "# Load custom prompt" >> /root/.bashrc
        echo "[[ -f /etc/profile.d/custom_prompt.sh ]] && source /etc/profile.d/custom_prompt.sh" >> /root/.bashrc
    fi
    
    local user_home=$(getent passwd "$USERNAME" | cut -d: -f6)
    local user_bashrc="${user_home}/.bashrc"
    if [[ -f "$user_bashrc" ]] && ! grep -q "custom_prompt.sh" "$user_bashrc"; then
        echo "" >> "$user_bashrc"
        echo "# Load custom prompt" >> "$user_bashrc"
        echo "[[ -f /etc/profile.d/custom_prompt.sh ]] && source /etc/profile.d/custom_prompt.sh" >> "$user_bashrc"
        chown "$USERNAME:$USERNAME" "$user_bashrc"
    fi
}

setup_ssh_keys() {
    log_info "Setting up SSH keys..."
    
    # Setup root's authorized_keys
    local root_ssh_dir="/root/.ssh"
    local root_authorized_keys="${root_ssh_dir}/authorized_keys"
    
    log_info "Creating SSH directory for root..."
    mkdir -p "$root_ssh_dir"
    chmod 700 "$root_ssh_dir"
    
    log_info "Adding SSH public key to root's authorized_keys..."
    echo "$SSH_PUBLIC_KEY" > "$root_authorized_keys"
    chmod 600 "$root_authorized_keys"
    log_info "Root's SSH public key added successfully"
    
    # Setup user's authorized_keys
    local user_home=$(getent passwd "$USERNAME" | cut -d: -f6)
    local user_ssh_dir="${user_home}/.ssh"
    local user_authorized_keys="${user_ssh_dir}/authorized_keys"
    
    log_info "Creating SSH directory for user $USERNAME..."
    mkdir -p "$user_ssh_dir"
    chmod 700 "$user_ssh_dir"
    chown "$USERNAME:$USERNAME" "$user_ssh_dir"
    
    log_info "Adding SSH public key to user's authorized_keys..."
    echo "$SSH_PUBLIC_KEY" > "$user_authorized_keys"
    chmod 600 "$user_authorized_keys"
    chown "$USERNAME:$USERNAME" "$user_authorized_keys"
    log_info "User's SSH public key added successfully"
    
    log_info "SSH keys configured successfully for root and $USERNAME"
}

install_docker() {
    log_info "Installing Docker..."
    
    if command -v docker &> /dev/null; then
        log_warn "Docker is already installed. Skipping installation."
    else
        log_info "Waiting for package manager to be available..."
        while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
            sleep 1
        done
        
        log_info "Downloading and installing Docker..."
        curl -fsSL https://get.docker.com | sh
        
        if command -v docker &> /dev/null; then
            log_info "Docker installed successfully"
        else
            log_error "Docker installation failed"
            exit 1
        fi
    fi
    
    log_info "Adding user $USERNAME to docker group..."
    usermod -aG docker "$USERNAME"
    log_info "User $USERNAME added to docker group"
    
    log_warn "Note: User may need to log out and log back in for docker group changes to take effect"
}

configure_sysctl() {
    log_info "Configuring system hardening..."
    
    local sysctl_conf="/etc/sysctl.conf"
    local sysctl_backup="${sysctl_conf}.backup.$(date +%Y%m%d_%H%M%S)"
    
    $SUDO_CMD cp "$sysctl_conf" "$sysctl_backup"
    log_info "sysctl.conf backed up to: $sysctl_backup"
    
    local configs=(
        "net.ipv4.icmp_echo_ignore_all=1"
        "net.ipv4.tcp_syncookies=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    
    for config in "${configs[@]}"; do
        local key=$(echo "$config" | cut -d'=' -f1)
        if ! $SUDO_CMD grep -q "^${key}" "$sysctl_conf"; then
            echo "$config" | $SUDO_CMD tee -a "$sysctl_conf" > /dev/null
            log_info "Added: $config"
        else
            $SUDO_CMD sed -i "s|^${key}=.*|${config}|" "$sysctl_conf"
            log_info "Updated: $config"
        fi
    done
    
    $SUDO_CMD sysctl -p
    
    log_info "System hardening configured successfully"
}

disable_ipv6() {
    log_info "Disabling IPv6..."
    
    $SUDO_CMD tee /etc/systemd/system/disable-ipv6.service > /dev/null <<'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1

[Install]
WantedBy=multi-user.target
EOF
    
    $SUDO_CMD systemctl daemon-reload
    $SUDO_CMD systemctl enable --now disable-ipv6.service
    $SUDO_CMD sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null
    $SUDO_CMD sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null
    
    log_info "IPv6 disabled successfully"
}

configure_swap() {
    if [[ "$SWAP_SIZE_GB" == "0" ]]; then
        log_info "Swap configuration skipped (0 GB specified)"
        return
    fi
    
    log_info "Configuring swap (${SWAP_SIZE_GB}GB)..."
    
    local swap_file="/swapfile"
    local swap_size_mb=$((SWAP_SIZE_GB * 1024))
    
    if swapon --show | grep -q "$swap_file"; then
        log_info "Swap file already exists, resizing..."
        swapoff "$swap_file" 2>/dev/null || true
        rm -f "$swap_file"
    fi
    
    log_info "Creating ${SWAP_SIZE_GB}GB swap file (this may take a while)..."
    fallocate -l "${swap_size_mb}M" "$swap_file" 2>/dev/null || dd if=/dev/zero of="$swap_file" bs=1M count="$swap_size_mb" 2>/dev/null
    chmod 600 "$swap_file"
    mkswap "$swap_file"
    swapon "$swap_file"
    
    if ! grep -q "^$swap_file" /etc/fstab; then
        echo "$swap_file none swap sw 0 0" >> /etc/fstab
        log_info "Swap added to /etc/fstab for persistence"
    else
        log_info "Swap already in /etc/fstab"
    fi
    
    log_info "Setting swappiness to 10 (use swap only when RAM is low)..."
    if ! grep -q "^vm.swappiness" /etc/sysctl.conf; then
        echo "vm.swappiness=10" >> /etc/sysctl.conf
    else
        sed -i 's/^vm.swappiness=.*/vm.swappiness=10/' /etc/sysctl.conf
    fi
    sysctl -w vm.swappiness=10
    
    log_info "Swap configured successfully (${SWAP_SIZE_GB}GB, swappiness=10)"
}

main() {
    if [[ $# -gt 0 ]] && ([[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]); then
        show_help
    fi
    
    check_root
    check_ubuntu
    
    # Initialize SUDO_CMD (empty since we're running as root)
    SUDO_CMD=""
    
    prompt_user_input
    update_system
    create_user
    setup_ssh_keys
    install_docker
    
    log_info "Configuring SSH, firewall, and system settings..."
    
    configure_ssh
    configure_fail2ban
    configure_firewall
    configure_sysctl
    disable_ipv6
    configure_swap
    
    log_info "=========================================="
    log_info "Configuration completed successfully!"
    log_info "=========================================="
    log_warn "IMPORTANT:"
    log_warn "1. SSH is now configured on port $SSH_PORT"
    log_warn "2. Password authentication is disabled - ensure you have SSH keys configured"
    log_warn "3. Root login is disabled - use user: $USERNAME"
    log_warn "4. IPv6 has been disabled"
    log_warn "5. Docker has been installed and user $USERNAME added to docker group"
    log_warn "6. Test SSH connection before closing current session!"
    log_warn "7. User may need to log out/in for docker group permissions to take effect"
    echo ""
    
    log_info "Next steps:"
    log_info "You can now run install_node.sh to install remnawave node and netbird"
    log_info "Run: bash install_node.sh"
    echo ""
    
    log_info "Switching to user: $USERNAME"
    echo ""
    
    su - "$USERNAME"
}

main "$@"
