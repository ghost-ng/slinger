#!/usr/bin/env python3
"""
Post-installation script for Slinger cooperative agent dependencies
Run this after installing Slinger with pipx to set up agent build requirements
"""

import subprocess
import sys
import platform
import shutil


def run_command(cmd, shell=False):
    """Run a command and return success status"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def check_dependency(command):
    """Check if a command exists"""
    return shutil.which(command) is not None


def install_dependencies():
    """Install system dependencies based on platform"""
    system = platform.system().lower()

    print("🔧 Slinger Cooperative Agent Dependencies Installer")
    print("=" * 50)

    # Check current status
    cmake_available = check_dependency("cmake")
    gcc_available = check_dependency("gcc") or check_dependency("g++")

    print(f"Current status:")
    print(f"  CMake: {'✓ Available' if cmake_available else '✗ Not found'}")
    print(f"  C++ Compiler: {'✓ Available' if gcc_available else '✗ Not found'}")
    print()

    if cmake_available and gcc_available:
        print("✅ All dependencies are already installed!")
        print("You can now use: slinger agent build")
        return True

    print("Installing missing dependencies...")
    print()

    if system == "linux":
        # Detect Linux distribution
        try:
            with open("/etc/os-release") as f:
                os_info = f.read().lower()
        except:
            os_info = ""

        if "ubuntu" in os_info or "debian" in os_info:
            print("📦 Detected Ubuntu/Debian - installing via apt...")
            print("Running: sudo apt update && sudo apt install -y cmake build-essential")

            # Update package list
            success, stdout, stderr = run_command(["sudo", "apt", "update"])
            if not success:
                print(f"❌ Failed to update package list: {stderr}")
                return False

            # Install packages
            success, stdout, stderr = run_command(
                ["sudo", "apt", "install", "-y", "cmake", "build-essential"]
            )
            if not success:
                print(f"❌ Failed to install packages: {stderr}")
                return False

        elif "centos" in os_info or "rhel" in os_info or "fedora" in os_info:
            print("📦 Detected CentOS/RHEL/Fedora - installing via yum/dnf...")

            # Try dnf first, fallback to yum
            pkg_manager = "dnf" if check_dependency("dnf") else "yum"

            print(f"Running: sudo {pkg_manager} groupinstall -y 'Development Tools'")
            success, stdout, stderr = run_command(
                ["sudo", pkg_manager, "groupinstall", "-y", "Development Tools"]
            )
            if not success:
                print(f"❌ Failed to install Development Tools: {stderr}")
                return False

            print(f"Running: sudo {pkg_manager} install -y cmake")
            success, stdout, stderr = run_command(["sudo", pkg_manager, "install", "-y", "cmake"])
            if not success:
                print(f"❌ Failed to install CMake: {stderr}")
                return False

        else:
            print("⚠️  Unknown Linux distribution. Please install manually:")
            print("  - CMake: https://cmake.org/download/")
            print("  - C++ compiler (gcc/g++)")
            return False

    elif system == "darwin":  # macOS
        print("📦 Detected macOS - checking for Homebrew...")

        if not check_dependency("brew"):
            print("❌ Homebrew not found. Please install Homebrew first:")
            print(
                '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            )
            return False

        print("Running: brew install cmake")
        success, stdout, stderr = run_command(["brew", "install", "cmake"])
        if not success:
            print(f"❌ Failed to install CMake via Homebrew: {stderr}")
            return False

    elif system == "windows":
        print("🪟 Detected Windows")
        print("Please install dependencies manually:")
        print("  1. Download CMake from: https://cmake.org/download/")
        print("  2. Install Visual Studio Build Tools or Visual Studio Community")
        print("     https://visualstudio.microsoft.com/downloads/")
        print()
        print("Alternative: Install via Chocolatey:")
        print("  choco install cmake visualstudio2022buildtools")
        return False

    else:
        print(f"⚠️  Unsupported platform: {system}")
        return False

    # Verify installation
    print("\n🔍 Verifying installation...")
    cmake_available = check_dependency("cmake")
    gcc_available = check_dependency("gcc") or check_dependency("g++")

    print(f"  CMake: {'✓ Available' if cmake_available else '✗ Still not found'}")
    print(f"  C++ Compiler: {'✓ Available' if gcc_available else '✗ Still not found'}")

    if cmake_available and gcc_available:
        print("\n✅ All dependencies installed successfully!")
        print("You can now use: slinger agent build")
        return True
    else:
        print("\n❌ Some dependencies are still missing. Please install manually.")
        return False


def main():
    """Main installation function"""
    try:
        success = install_dependencies()

        if success:
            print("\n🚀 Test your installation:")
            print("  slinger agent info")
            print("  slinger agent build --dry-run")
            sys.exit(0)
        else:
            print("\n📖 For manual installation instructions, see:")
            print("  https://github.com/ghost-ng/slinger#agent-dependencies")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n⚠️  Installation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
