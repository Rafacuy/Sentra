#!/data/data/com.termux/files/usr/bin/bash

# ASCII Art and Color Definitions
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

# rocket launch 
rocket_launch() {
    frames=(
        "    ▲    "
        "   ▲▲▲   "
        "  ▲▲▲▲▲  "
        " ▲▲▲▲▲▲▲ "
        "    ▲    "
        "   ██    "
        "   ██    "
    )
    for i in {1..10}; do
        clear
        echo -e "\n\n"
        echo -e "${CYAN}${frames[$((i % ${#frames[@]}))]}${RESET}"
        echo -e "${GREEN}  Preparing script..${RESET}"
        sleep 0.2
    done
}

# rotating spinner
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Header 
clear
rocket_launch
sleep 0.3
clear
echo -e "${MAGENTA}"
cat << "EOF"
_______ _______ __   _ _______  ______ _______
|______ |______ | \  |    |    |_____/ |_____|
______| |______ |  \_|    |    |    \_ |     |
Developed by Rafacuy
EOF
echo -e "${RESET}"
echo -e "${YELLOW}============================================${RESET}"
echo -e "${CYAN}    Python Library Installation Fixer${RESET}"
echo -e "${YELLOW}============================================${RESET}"

# Main process
echo -e "\n${GREEN}[+] Starting SENTRA repair sequence...${RESET}"
sleep 2

# Package updates
echo -e "\n${YELLOW}[⚙] UPDATING PACKAGE REPOSITORIES${RESET}"
(pkg update -y > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ Repository update complete!${RESET}"

# Package upgrades
echo -e "\n${YELLOW}[⚙] UPGRADING SYSTEM PACKAGES${RESET}"
(pkg upgrade -y > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ System upgrade complete!${RESET}"

# Install dependencies
echo -e "\n${YELLOW}[⚙] INSTALLING BUILD DEPENDENCIES${RESET}"
echo -e "${CYAN}   (Python, Clang, libffi, OpenSSL, Rust, Git)${RESET}"
(pkg install -y python clang libffi openssl rust git golang > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ Build tools installed!${RESET}"

# Set environment flags
echo -e "\n${YELLOW}[⚙] CONFIGURING BUILD ENVIRONMENT${RESET}"
export LDFLAGS="-L/data/data/com.termux/files/usr/lib"
export CFLAGS="-I/data/data/com.termux/files/usr/include"
echo -e "${GREEN} ✓ Environment configured!${RESET}"

# Install Python dependencies
echo -e "\n${YELLOW}[⚙] UPGRADING PYTHON BUILD SYSTEM${RESET}"
(pip install --upgrade pip setuptools wheel > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ Python tools upgraded!${RESET}"

# Install cryptography
echo -e "\n${YELLOW}[⚙] COMPILING CRYPTOGRAPHY LIBRARY${RESET}"
echo -e "${CYAN}   (This may take 3-5 minutes)${RESET}"
(pip install cryptography > /dev/null 2>&1) &
spinner $!
echo -e "${GREEN} ✓ Cryptography installed!${RESET}"

# install tls-client
echo -e "\n${YELLOW}[⚙] DOWNLOADING TLS-CLIENT BINARY${RESET}"
mkdir -p bin/
curl -L https://github.com/daffainfo/tls-client-binaries/raw/main/tls-client-linux-arm64 -o bin/tls-client > /dev/null 2>&1
chmod +x bin/tls-client
echo -e "${GREEN} ✓ tls-client binary installed!${RESET}"

# Install requirements
echo -e "\n${YELLOW}[⚙] INSTALLING PROJECT REQUIREMENTS${RESET}"
if [ -f requirements.txt ]; then
    pip install --no-cache-dir -r requirements.txt
else
    echo -e "${RED}✗ ERROR: requirements.txt not found.${RESET}"
fi
echo -e "${GREEN} ✓ Dependencies installed!${RESET}"

# Success animation
echo -e "\n${GREEN}[✓] SENTRA REPAIR COMPLETE!${RESET}"
echo -e "${YELLOW}Launching final checks...${RESET}"
for i in {1..10}; do
    printf "${MAGENTA}■${RESET}"
    sleep 0.1
    printf "${GREEN}■${RESET}"
    sleep 0.1
    printf "${CYAN}■${RESET}"
    sleep 0.1
done

# Final message
clear
echo -e "\n\n${GREEN}"
cat << "EOF"
____ _ _  _ _ ____ _  _ ____ ___ 
|___ | |\ | | [__  |__| |___ |  \
|    | | \| | ___] |  | |___ |__/
EOF
echo -e "${RESET}"
echo -e "${YELLOW}============================================${RESET}"
echo -e "${GREEN} All systems go! You can now run SENTRA ${RESET}"
echo -e "${YELLOW}============================================${RESET}"
echo -e "\n${CYAN}Tip:${RESET} If issues persist, restart your Termux session\n"