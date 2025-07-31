#!/usr/bin/env python3
import sys
import subprocess
import platform
import os


REQUIRED_MODULES = [
    "cryptography",
    "tqdm"
]


MAIN_PROGRAM_FILE = "ziocryptor.py"

def check_python_version():
    if sys.version_info < (3, 6):
        print("❌ Python 3.6 or higher is required.")
        sys.exit(1)
    print(f"✅ Python version OK: {platform.python_version()}")

def install_module(module_name):
    try:
        __import__(module_name)
        print(f"✅ Module already installed: {module_name}")
    except ImportError:
        print(f"📦 Installing module: {module_name} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_name , --break-system-packages])

def install_all_dependencies():
    for module in REQUIRED_MODULES:
        install_module(module)

def prompt_and_run():
    print("\n✅ All dependencies installed successfully.")
    answer = input("Do you want to run ZioleCryptor now? (y/n): ").lower()
    if answer == 'y':
        print("\n🚀 Running ZioleCryptor...")
        try:
            subprocess.run([sys.executable, MAIN_PROGRAM_FILE])
        except FileNotFoundError:
            print(f"❌ Error: '{MAIN_PROGRAM_FILE}' not found.")
    else:
        print("👍 Okay, program was not started.")

def main():
    print("\n🔧 ZioleCryptor Auto Installer & Launcher")
    check_python_version()
    install_all_dependencies()
    prompt_and_run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Process cancelled by user.")
