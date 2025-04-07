#!/bin/bash

# Function to check if python3 is installed
check_python3() {
  if command -v python3 &> /dev/null
  then
    echo "Python3 is already installed."
    return 0
  else
    echo "Python3 is not installed."
    return 1
  fi
}

# Function to install python3 on Debian-based systems
install_python3_debian() {
    echo "Installing Python 3 on Debian-based system..."
    sudo apt update
    sudo apt install -y python3 python3-pip
}

# Function to install python3 on RedHat-based systems
install_python3_redhat() {
    echo "Installing Python 3 on Red Hat-based system..."
    sudo yum update -y
    sudo yum install -y python3 python3-pip
}

# Function to install python3 on Arch-based systems
install_python3_arch() {
    echo "Installing Python 3 on Arch-based system..."
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm python python-pip
}

# Exit success if python3 is already installed
# Escape '$' when used during echo command to download script on remote host using raw mode
check_python3
if [ \$? -eq 0 ]; then
  exit 0
else
  echo "Proceeding with installation..."
fi

# Detect the operating system and install python3 accordingly
if [ -f /etc/debian_version ]; then
    install_python3_debian
elif [ -f /etc/redhat-release ]; then
    install_python3_redhat
elif [ -f /etc/arch-release ]; then
    install_python3_arch
else
    echo "Unsupported Linux distribution."
    exit 1
fi

# Verify installation
# Escape '$' when used during echo command to download script on remote host using raw mode
check_python3
if [ \$? -eq 0 ]; then
  echo "Python3 installation was successful."
else
  echo "Python3 installation failed."
  exit 1
fi
