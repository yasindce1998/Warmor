#!/usr/bin/env bash
set -euo pipefail

# Warmor Prerequisites Installer
# Detects your Linux distro and installs everything needed to build & run Warmor.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

INSTALLED=()
FAILED=()
SKIPPED=()

print_header() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}Warmor Prerequisites Installer${NC}                      ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  Kernel-level security enforcement platform          ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

log_skip() {
    echo -e "  ${YELLOW}⊘${NC} $1 (already installed)"
}

log_fail() {
    echo -e "  ${RED}✗${NC} $1"
    echo -e "    ${RED}Why:${NC} $2"
}

log_info() {
    echo -e "  ${BLUE}→${NC} $1"
}

section() {
    echo ""
    echo -e "${BOLD}[$1]${NC}"
}

# Detect distro
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_NAME="${PRETTY_NAME:-$ID}"
        DISTRO_VERSION="${VERSION_ID:-}"
        DISTRO_FAMILY=""

        case "$DISTRO_ID" in
            ubuntu|debian|pop|linuxmint|elementary|zorin|kali)
                DISTRO_FAMILY="debian"
                ;;
            fedora|rhel|centos|rocky|alma|ol)
                DISTRO_FAMILY="rhel"
                ;;
            arch|manjaro|endeavouros)
                DISTRO_FAMILY="arch"
                ;;
            opensuse*|sles)
                DISTRO_FAMILY="suse"
                ;;
            alpine)
                DISTRO_FAMILY="alpine"
                ;;
            *)
                DISTRO_FAMILY="unknown"
                ;;
        esac
    elif [ -f /etc/redhat-release ]; then
        DISTRO_ID="rhel"
        DISTRO_NAME=$(cat /etc/redhat-release)
        DISTRO_FAMILY="rhel"
    else
        DISTRO_ID="unknown"
        DISTRO_NAME="Unknown Linux"
        DISTRO_FAMILY="unknown"
    fi
}

# Check kernel version
check_kernel() {
    section "Kernel"
    local kver
    kver=$(uname -r)
    local major minor
    major=$(echo "$kver" | cut -d. -f1)
    minor=$(echo "$kver" | cut -d. -f2)

    if [ "$major" -gt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -ge 10 ]); then
        log_ok "Kernel $kver (>= 5.10 required)"
        INSTALLED+=("Kernel $kver")
    else
        log_fail "Kernel $kver" "Warmor requires kernel 5.10+ for eBPF/LSM support. Upgrade your kernel or use a newer distro."
        FAILED+=("Kernel (have $kver, need 5.10+)")
    fi

    # Check BTF support
    if [ -f /sys/kernel/btf/vmlinux ]; then
        log_ok "BTF enabled (CO-RE support)"
        INSTALLED+=("BTF/CO-RE")
    else
        log_fail "BTF not available" "Kernel was not compiled with CONFIG_DEBUG_INFO_BTF=y. CO-RE eBPF programs won't load. Use Ubuntu 22.04+, Fedora 36+, or Debian 12+."
        FAILED+=("BTF (CONFIG_DEBUG_INFO_BTF=y)")
    fi

    # Check LSM BPF
    if [ -f /sys/kernel/security/lsm ]; then
        local lsms
        lsms=$(cat /sys/kernel/security/lsm)
        if echo "$lsms" | grep -q "bpf"; then
            log_ok "LSM BPF enabled ($lsms)"
            INSTALLED+=("LSM-BPF")
        else
            log_fail "LSM BPF not in active LSMs" "Current LSMs: $lsms. Add 'bpf' to your kernel boot params: lsm=lockdown,capability,bpf (or append to existing list)."
            FAILED+=("LSM-BPF (not in kernel params)")
        fi
    fi
}

# Install system packages
install_system_packages() {
    section "System Packages"

    case "$DISTRO_FAMILY" in
        debian)
            install_debian_packages
            ;;
        rhel)
            install_rhel_packages
            ;;
        arch)
            install_arch_packages
            ;;
        alpine)
            install_alpine_packages
            ;;
        suse)
            install_suse_packages
            ;;
        *)
            log_fail "Package installation" "Unsupported distro: $DISTRO_NAME. Install manually: clang, llvm, libbpf-dev, linux-headers, pkg-config, make, git"
            FAILED+=("System packages (unsupported distro)")
            return
            ;;
    esac
}

install_debian_packages() {
    local packages=("build-essential" "clang" "llvm" "libbpf-dev" "pkg-config" "git" "curl")
    local headers_pkg="linux-headers-$(uname -r)"
    packages+=("$headers_pkg")

    local to_install=()

    for pkg in "${packages[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            log_skip "$pkg"
            SKIPPED+=("$pkg")
        else
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -gt 0 ]; then
        log_info "Installing: ${to_install[*]}"
        if sudo apt-get update -qq && sudo apt-get install -y -qq "${to_install[@]}"; then
            for pkg in "${to_install[@]}"; do
                log_ok "$pkg"
                INSTALLED+=("$pkg")
            done
        else
            for pkg in "${to_install[@]}"; do
                if ! dpkg -s "$pkg" &>/dev/null; then
                    log_fail "$pkg" "apt-get install failed. Check your sources.list or try: sudo apt-get update && sudo apt-get install $pkg"
                    FAILED+=("$pkg")
                fi
            done
        fi
    fi
}

install_rhel_packages() {
    local packages=("clang" "llvm" "libbpf-devel" "kernel-devel" "pkg-config" "make" "git" "curl")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if rpm -q "$pkg" &>/dev/null; then
            log_skip "$pkg"
            SKIPPED+=("$pkg")
        else
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -gt 0 ]; then
        log_info "Installing: ${to_install[*]}"
        if sudo dnf install -y "${to_install[@]}"; then
            for pkg in "${to_install[@]}"; do
                log_ok "$pkg"
                INSTALLED+=("$pkg")
            done
        else
            for pkg in "${to_install[@]}"; do
                if ! rpm -q "$pkg" &>/dev/null; then
                    log_fail "$pkg" "dnf install failed. Check your repos or try: sudo dnf install $pkg"
                    FAILED+=("$pkg")
                fi
            done
        fi
    fi
}

install_arch_packages() {
    local packages=("clang" "llvm" "libbpf" "linux-headers" "pkgconf" "make" "git" "curl")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if pacman -Qi "$pkg" &>/dev/null; then
            log_skip "$pkg"
            SKIPPED+=("$pkg")
        else
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -gt 0 ]; then
        log_info "Installing: ${to_install[*]}"
        if sudo pacman -S --noconfirm "${to_install[@]}"; then
            for pkg in "${to_install[@]}"; do
                log_ok "$pkg"
                INSTALLED+=("$pkg")
            done
        else
            for pkg in "${to_install[@]}"; do
                if ! pacman -Qi "$pkg" &>/dev/null; then
                    log_fail "$pkg" "pacman install failed. Try: sudo pacman -S $pkg"
                    FAILED+=("$pkg")
                fi
            done
        fi
    fi
}

install_alpine_packages() {
    local packages=("clang" "llvm" "libbpf-dev" "linux-headers" "pkgconf" "make" "git" "curl" "build-base")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if apk info -e "$pkg" &>/dev/null; then
            log_skip "$pkg"
            SKIPPED+=("$pkg")
        else
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -gt 0 ]; then
        log_info "Installing: ${to_install[*]}"
        if sudo apk add "${to_install[@]}"; then
            for pkg in "${to_install[@]}"; do
                log_ok "$pkg"
                INSTALLED+=("$pkg")
            done
        else
            for pkg in "${to_install[@]}"; do
                if ! apk info -e "$pkg" &>/dev/null; then
                    log_fail "$pkg" "apk add failed. Try: sudo apk add $pkg"
                    FAILED+=("$pkg")
                fi
            done
        fi
    fi
}

install_suse_packages() {
    local packages=("clang" "llvm" "libbpf-devel" "kernel-devel" "pkg-config" "make" "git" "curl")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if rpm -q "$pkg" &>/dev/null; then
            log_skip "$pkg"
            SKIPPED+=("$pkg")
        else
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -gt 0 ]; then
        log_info "Installing: ${to_install[*]}"
        if sudo zypper install -y "${to_install[@]}"; then
            for pkg in "${to_install[@]}"; do
                log_ok "$pkg"
                INSTALLED+=("$pkg")
            done
        else
            for pkg in "${to_install[@]}"; do
                if ! rpm -q "$pkg" &>/dev/null; then
                    log_fail "$pkg" "zypper install failed. Try: sudo zypper install $pkg"
                    FAILED+=("$pkg")
                fi
            done
        fi
    fi
}

# Install Go
install_go() {
    section "Go"

    local required_major=1
    local required_minor=26

    if command -v go &>/dev/null; then
        local go_version
        go_version=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        local go_major go_minor
        go_major=$(echo "$go_version" | cut -d. -f1)
        go_minor=$(echo "$go_version" | cut -d. -f2)

        if [ "$go_major" -gt "$required_major" ] || ([ "$go_major" -eq "$required_major" ] && [ "$go_minor" -ge "$required_minor" ]); then
            log_skip "Go $go_version (>= $required_major.$required_minor required)"
            SKIPPED+=("Go $go_version")
            return
        else
            log_info "Go $go_version found but need >= $required_major.$required_minor. Upgrading..."
        fi
    fi

    log_info "Installing Go $required_major.$required_minor..."

    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    case "$arch" in
        amd64|x86_64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)
            log_fail "Go" "Unsupported architecture: $arch. Download manually from https://go.dev/dl/"
            FAILED+=("Go (unsupported arch: $arch)")
            return
            ;;
    esac

    local go_tar="go${required_major}.${required_minor}.2.linux-${arch}.tar.gz"
    local go_url="https://go.dev/dl/${go_tar}"

    if curl -fsSL "$go_url" -o "/tmp/$go_tar"; then
        sudo rm -rf /usr/local/go
        if sudo tar -C /usr/local -xzf "/tmp/$go_tar"; then
            rm -f "/tmp/$go_tar"

            # Add to PATH for this session
            export PATH="/usr/local/go/bin:$PATH"

            # Add to shell profile if not already there
            local shell_rc=""
            if [ -f "$HOME/.bashrc" ]; then
                shell_rc="$HOME/.bashrc"
            elif [ -f "$HOME/.zshrc" ]; then
                shell_rc="$HOME/.zshrc"
            elif [ -f "$HOME/.profile" ]; then
                shell_rc="$HOME/.profile"
            fi

            if [ -n "$shell_rc" ] && ! grep -q '/usr/local/go/bin' "$shell_rc"; then
                echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$shell_rc"
                log_info "Added Go to PATH in $shell_rc"
            fi

            log_ok "Go $(go version | grep -oP 'go\K[0-9]+\.[0-9]+\.[0-9]+')"
            INSTALLED+=("Go ${required_major}.${required_minor}")
        else
            log_fail "Go" "Failed to extract archive. Check disk space and permissions on /usr/local/"
            FAILED+=("Go")
        fi
    else
        log_fail "Go" "Download failed. Check internet connection or download manually from https://go.dev/dl/"
        FAILED+=("Go")
    fi
}

# Install Rust
install_rust() {
    section "Rust"

    local required_minor=70

    if command -v rustc &>/dev/null; then
        local rust_version
        rust_version=$(rustc --version | grep -oP '[0-9]+\.[0-9]+\.[0-9]+')
        local rust_minor
        rust_minor=$(echo "$rust_version" | cut -d. -f2)

        if [ "$rust_minor" -ge "$required_minor" ]; then
            log_skip "Rust $rust_version (>= 1.$required_minor required)"
            SKIPPED+=("Rust $rust_version")
        else
            log_info "Rust $rust_version found but need >= 1.$required_minor. Upgrading..."
            if rustup update stable; then
                log_ok "Rust upgraded to $(rustc --version | grep -oP '[0-9]+\.[0-9]+\.[0-9]+')"
                INSTALLED+=("Rust (upgraded)")
            else
                log_fail "Rust upgrade" "rustup update failed. Try: rustup update stable"
                FAILED+=("Rust (upgrade)")
            fi
        fi
    else
        log_info "Installing Rust via rustup..."
        if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable; then
            source "$HOME/.cargo/env" 2>/dev/null || true
            export PATH="$HOME/.cargo/bin:$PATH"
            log_ok "Rust $(rustc --version | grep -oP '[0-9]+\.[0-9]+\.[0-9]+')"
            INSTALLED+=("Rust")
        else
            log_fail "Rust" "rustup installer failed. Check internet connection or install manually: https://rustup.rs"
            FAILED+=("Rust")
            return
        fi
    fi

    # Install the wasm32-unknown-unknown target (policies are built for it)
    if rustup target list --installed | grep -qx "wasm32-unknown-unknown"; then
        log_skip "wasm32-unknown-unknown target"
        SKIPPED+=("wasm32-unknown-unknown")
    else
        log_info "Adding wasm32-unknown-unknown target..."
        if rustup target add wasm32-unknown-unknown; then
            log_ok "wasm32-unknown-unknown target"
            INSTALLED+=("wasm32-unknown-unknown target")
        else
            log_fail "wasm32-unknown-unknown" "rustup target add failed. Try: rustup target add wasm32-unknown-unknown"
            FAILED+=("wasm32-unknown-unknown target")
        fi
    fi
}

# Print summary
print_summary() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Summary${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Distro:  ${BOLD}$DISTRO_NAME${NC}"
    echo ""

    if [ ${#INSTALLED[@]} -gt 0 ]; then
        echo -e "  ${GREEN}Installed (${#INSTALLED[@]}):${NC}"
        for item in "${INSTALLED[@]}"; do
            echo -e "    ${GREEN}✓${NC} $item"
        done
        echo ""
    fi

    if [ ${#SKIPPED[@]} -gt 0 ]; then
        echo -e "  ${YELLOW}Already installed (${#SKIPPED[@]}):${NC}"
        for item in "${SKIPPED[@]}"; do
            echo -e "    ${YELLOW}⊘${NC} $item"
        done
        echo ""
    fi

    if [ ${#FAILED[@]} -gt 0 ]; then
        echo -e "  ${RED}Still required (${#FAILED[@]}):${NC}"
        for item in "${FAILED[@]}"; do
            echo -e "    ${RED}✗${NC} $item"
        done
        echo ""
        echo -e "  ${RED}Some prerequisites are missing. Warmor may not build or run correctly.${NC}"
        echo -e "  ${RED}See the errors above for how to fix each one.${NC}"
        echo ""
        exit 1
    else
        echo -e "  ${GREEN}${BOLD}All prerequisites satisfied! You're ready to build Warmor.${NC}"
        echo ""
        echo -e "  Next steps:"
        echo -e "    ${BOLD}make all${NC}                    # Build everything"
        echo -e "    ${BOLD}sudo ./warmor-daemon${NC}        # Run the daemon"
        echo ""
    fi
}

# Main
main() {
    print_header

    # Check if running on Linux
    if [ "$(uname -s)" != "Linux" ]; then
        echo -e "${RED}Error: This script is for Linux only.${NC}"
        echo -e "For Windows, use WSL2. For macOS, see docs/PLATFORM_MACOS.md"
        exit 1
    fi

    detect_distro
    log_info "Detected: $DISTRO_NAME ($DISTRO_FAMILY family)"

    check_kernel
    install_system_packages
    install_go
    install_rust
    print_summary
}

main "$@"
