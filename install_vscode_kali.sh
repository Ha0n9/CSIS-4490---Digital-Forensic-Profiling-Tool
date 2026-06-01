#!/bin/bash

set -e

echo "======================================"
echo " Installing Visual Studio Code on Kali"
echo "======================================"

echo "[1/4] Updating system..."
sudo apt update && sudo apt upgrade -y

echo "[2/4] Installing dependencies..."
sudo apt install -y wget gpg apt-transport-https

echo "[3/4] Adding Microsoft GPG key..."
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
sudo install -o root -g root -m 644 microsoft.gpg /usr/share/keyrings/microsoft.gpg
rm microsoft.gpg

echo "[4/4] Adding VS Code repo..."
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | \
sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null

sudo apt update
sudo apt install -y code

echo "======================================"
echo " VS Code installed successfully!"
echo " Run: code"
echo "======================================"
