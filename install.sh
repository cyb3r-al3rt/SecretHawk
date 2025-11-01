#!/bin/bash

echo -e "\033[96m"
echo "  ____                    _   _   _                _    "
echo " / ___|  ___  ___ _ __ ___| |_| | | | __ ___      _| | __"
echo " \\___ \\ / _ \\/ __| '__/ _ \\ __| |_| |/ _\` \\ \\ /\\ / / |/ /"
echo "  ___) |  __/ (__| | |  __/ |_|  _  | (_| |\\ V  V /|   < "
echo " |____/ \\___|\\___|_|  \\___|\\__|_| |_|\\__,_| \\_/\\_/ |_|\\_\\"
echo -e "\033[0m"
echo ""
echo "SecretHawk Installation"
echo "====================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
fi

echo "[*] Installing Python dependencies..."
pip3 install --user requests urllib3 --quiet

echo "[*] Installing recommended Go tools..."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "[!] Go not found"
    echo "[*] Installing Go..."
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    rm go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Install tools in background
echo "[*] Installing reconnaissance tools (this may take a few minutes)..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null &
PID1=$!

go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null &
PID2=$!

go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null &
PID3=$!

go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null &
PID4=$!

wait $PID1 $PID2 $PID3 $PID4

echo "[*] Adding paths..."
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
export PATH=$PATH:$HOME/go/bin

# Make script executable
echo "[*] Setting up SecretHawk..."
chmod +x secrethawk.py

# Create symlink
sudo ln -sf $(pwd)/secrethawk.py /usr/local/bin/secrethawk

echo ""
echo "[+] Installation completed!"
echo ""
echo "Usage:"
echo "  secrethawk -d example.com"
echo ""
echo "Optional tools installed:"
echo "  - subfinder (subdomain enumeration)"
echo "  - gau (URL aggregation)"
echo "  - waybackurls (Wayback Machine)"
echo "  - katana (web crawling)"
echo ""
echo "Run: source ~/.bashrc"
echo ""
