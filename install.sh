#!/usr/bin/env bash
# =============================================================================
# matazero — Automated Cross-Platform Installer for Linux, Kali Linux & macOS
# =============================================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
cat << "EOF"
  __  __       _                            
 |  \/  |     | |                           
 | \  / | __ _| |_ __ _ _______ _ __ ___   
 | |\/| |/ _` | __/ _` |_  / _ \ '__/ _ \  
 | |  | | (_| | || (_| |/ /  __/ | | (_) | 
 |_|  |_|\__,_|\__\__,_/___\___|_|  \___/  
       Forensic Image Intelligence Toolkit
EOF
echo -e "${NC}"

echo -e "${CYAN}[*] Checking system environment...${NC}"

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[X] Python 3 is not installed. Please install Python 3.10 or newer.${NC}"
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo -e "${RED}[X] Python 3.10+ is required. Found Python $PY_VER${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] Found Python $PY_VER${NC}"

# Check Pip
if ! python3 -m pip --version &> /dev/null; then
    echo -e "${YELLOW}[!] pip not found. Installing pip...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3-pip python3-venv
    else
        echo -e "${RED}[X] Please install python3-pip.${NC}"
        exit 1
    fi
fi

# Directory setup
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$INSTALL_DIR"

echo -e "${CYAN}[*] Installing matazero core package...${NC}"
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -e .

# Install UNIX Man Page if running on Linux/macOS
if [ -f "docs/man/matazero.1" ]; then
    echo -e "${CYAN}[*] Installing man page (matazero.1)...${NC}"
    MAN_TARGET="/usr/local/share/man/man1"
    if [ -w "/usr/local/share/man/man1" ]; then
        mkdir -p "$MAN_TARGET"
        cp docs/man/matazero.1 "$MAN_TARGET/matazero.1"
        chmod 644 "$MAN_TARGET/matazero.1"
        echo -e "${GREEN}[OK] Man page installed to $MAN_TARGET/matazero.1${NC}"
    elif command -v sudo &> /dev/null && [ "$EUID" -ne 0 ]; then
        sudo mkdir -p "$MAN_TARGET" 2>/dev/null || true
        sudo cp docs/man/matazero.1 "$MAN_TARGET/matazero.1" 2>/dev/null || true
        sudo chmod 644 "$MAN_TARGET/matazero.1" 2>/dev/null || true
        echo -e "${GREEN}[OK] Man page installed to $MAN_TARGET/matazero.1 (via sudo)${NC}"
    fi
fi

# Optional Shell Completion Setup
echo -e "${CYAN}[*] Setting up shell autocompletion...${NC}"
if [ -d "$HOME/.bashrc" ] || [ -f "$HOME/.bashrc" ]; then
    if ! grep -q "_MATAZERO_COMPLETE=bash_source" "$HOME/.bashrc" 2>/dev/null; then
        echo 'eval "$(_MATAZERO_COMPLETE=bash_source matazero)"' >> "$HOME/.bashrc"
        echo -e "${GREEN}[OK] Bash autocompletion added to ~/.bashrc${NC}"
    fi
fi

if [ -f "$HOME/.zshrc" ]; then
    ZFUNC_DIR="$HOME/.zfunc"
    mkdir -p "$ZFUNC_DIR"
    matazero completion zsh > "$ZFUNC_DIR/_matazero" 2>/dev/null || true
    echo -e "${GREEN}[OK] Zsh autocompletion written to ~/.zfunc/_matazero${NC}"
fi

# Optional Ollama Setup
echo ""
echo -e "${CYAN}${BOLD}--- Local AI Vision Setup (Optional) ---${NC}"
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}[OK] Ollama is already installed.${NC}"
else
    echo -e "${YELLOW}[?] Would you like to install Ollama for offline local AI vision? [y/N]${NC}"
    read -r -t 15 INSTALL_OLLAMA || INSTALL_OLLAMA="n"
    if [[ "$INSTALL_OLLAMA" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}[*] Installing Ollama...${NC}"
        curl -fsSL https://ollama.com/install.sh | sh
    else
        echo -e "${YELLOW}[-] Skipping Ollama installation.${NC}"
    fi
fi

# Verification
echo ""
echo -e "${CYAN}[*] Verifying installation...${NC}"
if command -v matazero &> /dev/null; then
    echo -e "${GREEN}${BOLD}[✔] matazero successfully installed!${NC}"
    matazero --version
else
    echo -e "${GREEN}[✔] Installed! Run directly via:${NC} ${BOLD}python3 -m matazero --help${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}Installation Complete!${NC}"
echo -e "Try running:  ${CYAN}matazero --help${NC}"
echo -e "View manual:  ${CYAN}man matazero${NC}"
