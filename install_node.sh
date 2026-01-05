#!/bin/bash

set -euo pipefail

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_header() {
    clear
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Node Installation Setup          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
}

install_remnawave() {
    log_info "Installing remnawave node..."
    
    log_info "Downloading remnanode.sh script..."
    if ! curl -fsSL https://github.com/DigneZzZ/remnawave-scripts/raw/main/remnanode.sh -o remnanode.sh; then
        log_error "Failed to download remnanode.sh"
        return 1
    fi
    
    log_info "Making remnanode.sh executable..."
    chmod +x remnanode.sh
    
    log_info "Running remnanode.sh install..."
    if sudo bash remnanode.sh install; then
        log_info "remnawave node installed successfully"
        rm -f remnanode.sh
        return 0
    else
        log_error "remnawave node installation failed"
        rm -f remnanode.sh
        return 1
    fi
}

install_netbird() {
    log_info "Installing netbird..."
    
    if command -v netbird &> /dev/null; then
        log_warn "netbird is already installed. Skipping installation."
        return 0
    fi
    
    log_info "Downloading and installing netbird..."
    if curl -fsSL https://pkgs.netbird.io/install.sh | sh; then
        log_info "netbird installed successfully"
        return 0
    else
        log_error "netbird installation failed"
        return 1
    fi
}

configure_netbird() {
    log_info "Configuring netbird..."
    
    if ! command -v netbird &> /dev/null; then
        log_error "netbird is not installed"
        return 1
    fi
    
    while true; do
        read -p "Netbird setup key: " NETBIRD_SETUP_KEY
        if [[ -z "$NETBIRD_SETUP_KEY" ]]; then
            echo -e "${RED}✗${NC} Setup key cannot be empty"
            continue
        fi
        break
    done
    
    log_info "Setting up netbird with provided key..."
    if sudo netbird up --setup-key "$NETBIRD_SETUP_KEY"; then
        log_info "netbird configured successfully"
        return 0
    else
        log_error "netbird setup failed"
        return 1
    fi
}

main() {
    show_header
    
    log_info "This script will install remnawave node and netbird"
    echo ""
    
    local install_remnawave_node=false
    while true; do
        read -p "Install remnawave node? (y/n): " install_remnawave
        if [[ "$install_remnawave" =~ ^[Yy]$ ]]; then
            install_remnawave_node=true
            break
        elif [[ "$install_remnawave" =~ ^[Nn]$ ]]; then
            install_remnawave_node=false
            break
        else
            echo -e "${RED}✗${NC} Please enter 'y' or 'n'"
        fi
    done
    
    echo ""
    
    if [[ "$install_remnawave_node" == "true" ]]; then
        if ! install_remnawave; then
            log_error "Failed to install remnawave node"
            exit 1
        fi
        echo ""
    else
        log_info "Skipping remnawave node installation"
        echo ""
    fi
    
    log_info "Installing netbird..."
    if ! install_netbird; then
        log_error "Failed to install netbird"
        exit 1
    fi
    echo ""
    
    log_info "Configuring netbird..."
    if ! configure_netbird; then
        log_error "Failed to configure netbird"
        exit 1
    fi
    echo ""
    
    log_info "=========================================="
    log_info "Node installation completed successfully!"
    log_info "=========================================="
    
    if [[ "$install_remnawave_node" == "true" ]]; then
        log_info "✓ remnawave node installed"
    fi
    log_info "✓ netbird installed and configured"
    echo ""
}

main "$@"



