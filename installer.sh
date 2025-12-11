#!/bin/bash
# install_all_tools.sh

echo "📦 Installing Bug Hunter Tools..."
echo "================================="

# Update system
echo "[1/7] Updating system..."
sudo apt update && sudo apt upgrade -y

# Install basic packages
echo "[2/7] Installing basic packages..."
sudo apt install -y \
    curl wget git python3 python3-pip \
    jq golang nmap dnsutils whois \
    build-essential libssl-dev zlib1g-dev \
    libncurses5-dev libsqlite3-dev libreadline-dev \
    libgdbm-dev libdb5.3-dev libbz2-dev libexpat1-dev \
    liblzma-dev tk-dev libffi-dev

# Install Python packages
echo "[3/7] Installing Python packages..."
pip3 install --upgrade pip
pip3 install \
    requests beautifulsoup4 \
    waybackurls gau arjun paramspider \
    httpx sqlmap ssrfmap \
    markdown

# Install Go tools
echo "[4/7] Installing Go tools..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/devanshbatham/paramspider@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hahwul/dalfox/v2@latest

# Install Nuclei (advanced scanner)
echo "[5/7] Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates

# Install wordlists
echo "[6/7] Installing wordlists..."
sudo apt install -y seclists
if [ ! -d "/usr/share/wordlists/SecLists" ]; then
    cd /usr/share/wordlists/
    sudo git clone https://github.com/danielmiessler/SecLists.git
fi

# Create custom wordlists directory
echo "[7/7] Setting up directories..."
mkdir -p ~/wordlists
mkdir -p ~/tools

# Download common parameter wordlist
wget -O ~/wordlists/parameters.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt

echo ""
echo "✅ Installation complete!"
echo ""
echo "📁 Important directories:"
echo "   ~/wordlists/      - Wordlists for fuzzing"
echo "   ~/go/bin/         - Go tools location"
echo "   ~/.local/bin/     - Python tools location"
echo ""
echo "🛠️  Verify installation:"
echo "   sqlmap --version"
echo "   ffuf -V"
echo "   arjun -h"
echo ""
echo "🔧 Add to PATH (add to ~/.bashrc):"
echo "   export PATH=\$PATH:\$HOME/go/bin:\$HOME/.local/bin"
