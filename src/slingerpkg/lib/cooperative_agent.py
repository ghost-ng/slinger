#!/usr/bin/env python3
"""
Cooperative Agent Builder for Slinger
Generates polymorphic C++ agents for named pipe command execution
"""

import os
import sys
import random
import string
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any


class AgentBuilder:
    """Builds polymorphic C++ agents with advanced obfuscation"""

    def __init__(self, base_path: str, debug: bool = False):
        self.base_path = Path(base_path)
        self.template_dir = self.base_path / "lib" / "agent_templates"
        self.build_dir = self.base_path / "build" / "agent"
        self.output_dir = Path.home() / ".slinger" / "agents"

        # Polymorphic encryption seeds
        self.encryption_seed = random.randint(1, 65535)
        self.layout_seed = random.randint(1000, 9999)

        # Store debug flag for agent compilation
        self.debug = debug

    def generate_random_string(self, length: int = 8) -> str:
        """Generate random string for obfuscation"""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def create_polymorphic_template(self, arch: str) -> Dict[str, Any]:
        """Create polymorphic variations of templates"""

        # Generate unique function name mappings
        func_mappings = {
            "main_entry_point": f"func_{self.generate_random_string()}",
            "handle_pipe_communication": f"pipe_{self.generate_random_string()}",
            "process_command_request": f"cmd_{self.generate_random_string()}",
            "cleanup_resources": f"clean_{self.generate_random_string()}",
            "generate_pipe_name": f"gen_{self.generate_random_string()}",
            "process_commands": f"proc_{self.generate_random_string()}",
            "run": f"run_{self.generate_random_string()}",
            "cleanup": f"cleanup_{self.generate_random_string()}",
        }

        # Generate unique string encryption keys
        string_keys = {
            "pipe_name_key": random.randint(100, 999),
            "success_key": random.randint(100, 999),
            "error_key": random.randint(100, 999),
            "exit_key": random.randint(100, 999),
        }

        build_id = f"{random.randint(10000, 99999)}_{arch}"

        config = {
            "arch": arch,
            "encryption_seed": self.encryption_seed,
            "layout_seed": self.layout_seed,
            "function_mappings": func_mappings,
            "string_keys": string_keys,
            "build_id": build_id,
        }

        return config

    def apply_template_obfuscation(self, template_path: Path, config: Dict[str, Any]) -> str:
        """Apply obfuscation to template files"""

        with open(template_path, "r") as f:
            content = f.read()

        # Replace function name mappings
        for original, obfuscated in config["function_mappings"].items():
            pattern = f"OBF_FUNC_NAME({original})"
            content = content.replace(pattern, obfuscated)

        # NOTE: BUILD_SEED and other encryption seeds are defined via CMake add_definitions()
        # This ensures the preprocessor directives in obfuscation.h work correctly
        # No source code replacements needed for encryption seeds

        return content

    def setup_build_environment(self, arch: str) -> Path:
        """Setup build environment for specific architecture"""

        build_path = self.build_dir / f"build_{arch}_{self.encryption_seed}"

        # Clean old build directory if it exists to prevent stale template reuse
        if build_path.exists():
            import shutil

            shutil.rmtree(build_path)

        build_path.mkdir(parents=True, exist_ok=True)

        return build_path

    def generate_cmake_config(self, build_path: Path, arch: str, config: Dict[str, Any]) -> None:
        """Generate CMake configuration for polymorphic build"""

        # Always cross-compile for Windows targets using MinGW
        # This produces Windows PE executables regardless of host platform

        if arch == "x86":
            compiler_prefix = "i686-w64-mingw32"
        else:  # x64
            compiler_prefix = "x86_64-w64-mingw32"

        cmake_content = f"""
cmake_minimum_required(VERSION 3.15)
project(SlingerAgent_{config['build_id']})

# Cross-compilation setup for Windows targets
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER {compiler_prefix}-gcc)
set(CMAKE_CXX_COMPILER {compiler_prefix}-g++)
set(CMAKE_RC_COMPILER {compiler_prefix}-windres)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Target architecture definitions
if("{arch}" STREQUAL "x64")
    add_definitions(-DARCH_X64)
elseif("{arch}" STREQUAL "x86")
    add_definitions(-DARCH_X86)
endif()

# MinGW cross-compilation settings for Windows
set(CMAKE_CXX_FLAGS "${{CMAKE_CXX_FLAGS}} -O3 -ffunction-sections -fdata-sections -fno-stack-protector")
set(CMAKE_EXE_LINKER_FLAGS "${{CMAKE_EXE_LINKER_FLAGS}} -Wl,--gc-sections -s -static -static-libgcc -static-libstdc++")"""

        # Add obfuscation flags if enabled
        if config.get("obfuscate"):
            cmake_content += """

# Maximum obfuscation mode
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fomit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--strip-debug")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-export-dynamic -Wl,--exclude-libs,ALL")
add_definitions(-DNDEBUG -DNO_DEBUG_LOGS)"""

        cmake_content += """

# Windows libraries (including bcrypt for crypto)
set(PLATFORM_LIBS kernel32 user32 advapi32 shell32 ws2_32 bcrypt)"""

        # Add common sections for both platforms
        cmake_content += f"""

# Polymorphic definitions
add_definitions(
    -DBUILD_SEED={config['encryption_seed']}
    -DENCRYPTION_SEED={config['encryption_seed']}
    -DLAYOUT_SEED={config['layout_seed']}
    -DBUILD_ID="{config['build_id']}"
)"""

        # Add custom pipe name if specified
        if config.get("custom_pipe_name"):
            cmake_content += f"""
add_definitions(-DCUSTOM_PIPE_NAME="{config['custom_pipe_name']}")"""

        # Add debug mode if enabled
        if config.get("debug_mode"):
            cmake_content += f"""
add_definitions(-DDEBUG_MODE)"""

        # Add passphrase if specified
        if config.get("passphrase"):
            cmake_content += f"""
add_definitions(-DAGENT_PASSPHRASE="{config['passphrase']}")"""

        build_id = config["build_id"]
        cmake_section = f"""

# Source files
add_executable(slinger_agent_{build_id}
    agent_main.cpp
)

# Link libraries
target_link_libraries(slinger_agent_{build_id} PRIVATE ${{PLATFORM_LIBS}})

# Output naming
set_target_properties(slinger_agent_{build_id} PROPERTIES
    OUTPUT_NAME "agent_{build_id}"
    RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin"
)
"""
        cmake_content += cmake_section

        # Add post-build obfuscation steps if enabled
        if config.get("obfuscate"):
            cmake_content += f"""

# Post-build obfuscation - strip symbols
add_custom_command(TARGET slinger_agent_{build_id} POST_BUILD
    COMMAND ${{CMAKE_STRIP}} --strip-all --strip-unneeded $<TARGET_FILE:slinger_agent_{build_id}>.exe
    COMMENT "Stripping all symbols and debug information..."
)
"""

        # Add UPX compression if path provided
        if config.get("upx_path"):
            upx_binary = config["upx_path"]
            cmake_content += f"""

# UPX compression
add_custom_command(TARGET slinger_agent_{build_id} POST_BUILD
    COMMAND {upx_binary} --best --lzma --force $<TARGET_FILE:slinger_agent_{build_id}>.exe
    COMMENT "Compressing with UPX (LZMA)..."
)
"""

        cmake_file = build_path / "CMakeLists.txt"
        with open(cmake_file, "w") as f:
            f.write(cmake_content)

    def check_build_dependencies(self) -> Dict[str, bool]:
        """Check if required build tools are available"""
        dependencies = {}

        # Check for CMake
        try:
            result = subprocess.run(["cmake", "--version"], capture_output=True, text=True)
            dependencies["cmake"] = result.returncode == 0
        except FileNotFoundError:
            dependencies["cmake"] = False

        # Check for C++ compiler (try multiple)
        cpp_compilers = ["g++", "clang++", "cl.exe"]
        dependencies["cpp_compiler"] = False
        for compiler in cpp_compilers:
            try:
                result = subprocess.run([compiler, "--version"], capture_output=True, text=True)
                if result.returncode == 0:
                    dependencies["cpp_compiler"] = True
                    dependencies["compiler_found"] = compiler
                    break
            except FileNotFoundError:
                continue

        return dependencies

    def build_agent(
        self,
        arch: str,
        encryption: bool = True,
        debug: bool = False,
        custom_pipe_name: str = "slinger",
        custom_binary_name: str = None,
        passphrase: str = None,
        obfuscate: bool = False,
        upx_path: str = None,
    ) -> Optional[Path]:
        """Build polymorphic agent for specific architecture"""

        if debug:
            print(f"[DEBUG] build_agent called with passphrase={'<set>' if passphrase else 'None'}")

        print(f"Building {arch} agent with encryption: {encryption}")
        if custom_pipe_name:
            print(f"  Pipe name: {custom_pipe_name}")
        else:
            print(f"  Pipe name: <time-based random>")
        if passphrase:
            print(f"  Authentication: ENABLED (passphrase-based encryption)")
        else:
            print(f"  Authentication: DISABLED (XOR encoding only)")
        if debug:
            print(f"  Debug mode: ENABLED (agent will log runtime debug info)")

        # Check build dependencies first
        deps = self.check_build_dependencies()
        if not deps.get("cmake", False):
            print("ERROR: CMake not found. Please install CMake.")
            print()
            print("📦 Quick Install Commands:")
            print("  Ubuntu/Debian: sudo apt update && sudo apt install cmake build-essential")
            print(
                "  CentOS/RHEL:   sudo yum groupinstall 'Development Tools' && sudo yum install cmake"
            )
            print(
                "  Fedora:        sudo dnf groupinstall 'Development Tools' && sudo dnf install cmake"
            )
            print("  macOS:         brew install cmake")
            print("  Windows:       Download from https://cmake.org/download/")
            print()
            print("🚀 Or use the automated installer:")
            print("  slinger-setup-agent")
            print()
            return None

        if not deps.get("cpp_compiler", False):
            print("ERROR: No C++ compiler found.")
            print()
            print("📦 Quick Install Commands:")
            print("  Ubuntu/Debian: sudo apt install build-essential")
            print("  CentOS/RHEL:   sudo yum groupinstall 'Development Tools'")
            print("  Fedora:        sudo dnf groupinstall 'Development Tools'")
            print("  macOS:         Xcode Command Line Tools (auto-installed with brew)")
            print("  Windows:       Install Visual Studio Build Tools")
            print()
            print("🚀 Or use the automated installer:")
            print("  slinger-setup-agent")
            print()
            return None

        if debug:
            print(f"Using compiler: {deps.get('compiler_found', 'unknown')}")

        # Generate polymorphic configuration
        config = self.create_polymorphic_template(arch)
        if custom_pipe_name:
            config["custom_pipe_name"] = custom_pipe_name
        if debug:
            config["debug_mode"] = True
        if passphrase:
            config["passphrase"] = passphrase
        if obfuscate:
            config["obfuscate"] = True
        if upx_path:
            config["upx_path"] = upx_path

        # Setup build environment
        build_path = self.setup_build_environment(arch)

        try:
            # Copy and obfuscate template files
            template_files = [
                "agent_main.cpp",
                "obfuscation.h",
                "pipe_core.h",
                "command_executor.h",
                "crypto.h",
                "dh_x25519.h",
                "auth_protocol.h",
            ]

            for template_file in template_files:
                template_path = self.template_dir / template_file
                if template_path.exists():
                    obfuscated_content = self.apply_template_obfuscation(template_path, config)
                    output_path = build_path / template_file
                    with open(output_path, "w") as f:
                        f.write(obfuscated_content)

            # Generate CMake configuration
            self.generate_cmake_config(build_path, arch, config)

            # Configure build
            configure_cmd = [
                "cmake",
                "-S",
                str(build_path),
                "-B",
                str(build_path / "build"),
                "-DCMAKE_BUILD_TYPE=Release",
            ]

            # Cross-compilation doesn't need platform-specific flags
            # CMake configuration handles all compiler settings

            if debug:
                print(f"Running CMake configure: {' '.join(configure_cmd)}")

            result = subprocess.run(configure_cmd, capture_output=True, text=True, cwd=build_path)

            if result.returncode != 0:
                print(f"CMake configure failed:")
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
                return None

            if debug:
                print("CMake configure successful")

            # Build
            build_cmd = [
                "cmake",
                "--build",
                str(build_path / "build"),
                "--config",
                "Release",
                "--parallel",
            ]

            if debug:
                print(f"Running CMake build: {' '.join(build_cmd)}")

            result = subprocess.run(build_cmd, capture_output=True, text=True, cwd=build_path)

            if result.returncode != 0:
                print(f"Build failed:")
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
                return None

            if debug:
                print("Build completed successfully")

            # Find output executable
            output_pattern = f"agent_{config['build_id']}"

            # Try different possible output directories
            possible_dirs = [
                build_path / "build" / "bin" / "Release",  # Windows with separate Release folder
                build_path / "build" / "Release",  # Windows Release folder
                build_path / "build" / "bin",  # Unix Makefiles
                build_path / "build",  # Direct build output
            ]

            bin_dir = None
            for dir_path in possible_dirs:
                if dir_path.exists():
                    bin_dir = dir_path
                    break

            if bin_dir is None:
                print("Could not find build output directory")
                return None

            for ext in [".exe", ""]:
                output_file = bin_dir / f"{output_pattern}{ext}"
                if debug:
                    print(f"Checking for executable: {output_file}")
                if output_file.exists():
                    # Copy to final output directory
                    self.output_dir.mkdir(parents=True, exist_ok=True)
                    # Use custom name if provided, otherwise default naming
                    if custom_binary_name:
                        # Include arch in custom name
                        base_name = custom_binary_name.replace(".exe", "")
                        final_output = self.output_dir / f"{base_name}_{arch}.exe"
                    else:
                        # Always use .exe extension since we're cross-compiling for Windows
                        final_output = self.output_dir / (
                            f"slinger_agent_{arch}_{config['encryption_seed']}.exe"
                        )
                    shutil.copy2(output_file, final_output)

                    print(f"Agent built successfully: {final_output}")
                    print(f"  Architecture: {arch}")
                    print(f"  Encryption seed: {config['encryption_seed']}")
                    print(f"  Build ID: {config['build_id']}")

                    # Show pipe name information
                    if config.get("custom_pipe_name"):
                        print(f"  Pipe name: {config['custom_pipe_name']} (custom)")
                    else:
                        print(f"  Pipe name: <time-based random> (determined at runtime)")

                    # Show authentication status
                    if config.get("passphrase"):
                        print(
                            f"  Authentication: ENABLED (passphrase-based AES-256-GCM encryption)"
                        )
                    else:
                        print(f"  Authentication: DISABLED (XOR encoding only)")

                    # Show debug mode status
                    if config.get("debug_mode"):
                        print(f"  Debug mode: ENABLED")
                        print(f"  Agent will log to: <agent_directory>\\slinger_agent_debug.log")

                    # Save to build registry
                    self._save_to_build_registry(final_output, arch, config)

                    return final_output

            print(f"Could not find built executable in {bin_dir}")
            if debug:
                print(f"Looking for pattern: {output_pattern}")
                print(f"Files in directory:")
                for f in bin_dir.iterdir():
                    print(f"  {f.name}")
            return None

        except Exception as e:
            print(f"Build error: {e}")
            if debug:
                import traceback

                traceback.print_exc()
            return None

    def build_all_architectures(self, encryption: bool = True) -> List[Path]:
        """Build agents for all supported architectures"""

        built_agents = []

        for arch in ["x86", "x64"]:
            agent_path = self.build_agent(arch, encryption)
            if agent_path:
                built_agents.append(agent_path)

        return built_agents

    def get_build_info(self) -> Dict[str, Any]:
        """Get information about current build configuration"""

        # Check build dependencies
        deps = self.check_build_dependencies()

        return {
            "template_dir": str(self.template_dir),
            "build_dir": str(self.build_dir),
            "output_dir": str(self.output_dir),
            "encryption_seed": self.encryption_seed,
            "layout_seed": self.layout_seed,
            "supported_architectures": ["x86", "x64"],
            "dependencies": {
                "cmake_available": deps.get("cmake", False),
                "cpp_compiler_available": deps.get("cpp_compiler", False),
                "compiler_found": deps.get("compiler_found", "None"),
            },
            "template_files": [
                "obfuscation.h - C++ obfuscation framework",
                "pipe_core.h - Named pipe communication",
                "command_executor.h - Command execution engine",
                "agent_main.cpp - Main agent implementation",
                "build_config.cmake - CMake build configuration",
            ],
            "features": [
                "Named pipe command execution",
                "Polymorphic encryption",
                "Function name obfuscation",
                "String literal obfuscation",
                "Control flow obfuscation",
                "No sandbox detection",
                "No process detection",
            ],
        }

    def _save_to_build_registry(self, agent_path, arch, config):
        """Save built agent information to build registry"""
        try:
            import os
            import json
            from pathlib import Path
            import datetime

            # Create build registry directory
            registry_dir = Path.home() / ".slinger" / "builds"
            registry_dir.mkdir(parents=True, exist_ok=True)
            registry_path = registry_dir / "built_agents.json"

            # Load existing registry
            registry = {}
            if registry_path.exists():
                try:
                    with open(registry_path, "r") as f:
                        registry = json.load(f)
                except:
                    pass

            # Agent path as key
            agent_key = str(agent_path)

            # Store agent build information
            registry[agent_key] = {
                "path": str(agent_path),
                "filename": os.path.basename(agent_path),
                "architecture": arch,
                "encryption_seed": config["encryption_seed"],
                "build_id": config["build_id"],
                "pipe_name": config.get("custom_pipe_name"),  # None for time-based
                "pipe_type": "custom" if config.get("custom_pipe_name") else "time-based",
                "passphrase": config.get("passphrase"),  # None if not set
                "auth_enabled": config.get("passphrase") is not None,
                "built_at": str(datetime.datetime.now()),
                "file_size": os.path.getsize(agent_path) if os.path.exists(agent_path) else 0,
            }

            # Save updated registry
            with open(registry_path, "w") as f:
                json.dump(registry, f, indent=2)

        except Exception as e:
            print(f"Warning: Failed to save to build registry: {e}")


def build_cooperative_agent(
    arch: str = "both",
    encryption: bool = True,
    debug: bool = False,
    base_path: str = None,
    custom_pipe_name: str = "slinger",
    custom_binary_name: str = None,
    passphrase: str = None,
    obfuscate: bool = False,
    upx_path: str = None,
) -> List[str]:
    """
    Main function to build cooperative agents

    Args:
        arch: Architecture to build ('x86', 'x64', or 'both')
        encryption: Enable polymorphic encryption
        debug: Enable debug output
        base_path: Base project path (auto-detected if None)
        custom_pipe_name: Custom pipe name for agent communication
        custom_binary_name: Custom binary name for output
        passphrase: Passphrase for encrypted authentication
        obfuscate: Enable maximum obfuscation (strip symbols, hide visibility)
        upx_path: Path to UPX binary for compression (None = skip UPX)

    Returns:
        List of built agent paths
    """

    if debug:
        print(
            f"[DEBUG] build_cooperative_agent called with passphrase={'<set>' if passphrase else 'None'}"
        )

    if base_path is None:
        # Calculate path to project root from src/slingerpkg/lib/cooperative_agent.py
        # Go up 4 directories: cooperative_agent.py -> lib -> slingerpkg -> src -> project_root
        file_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(file_dir)))
    builder = AgentBuilder(base_path, debug=debug)

    if debug:
        info = builder.get_build_info()
        print("Build Configuration:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        print()

    built_agents = []

    if arch == "both":
        # Always use custom_pipe_name (defaults to "slinger")
        for target_arch in ["x86", "x64"]:
            agent_path = builder.build_agent(
                target_arch,
                encryption,
                debug,
                custom_pipe_name,
                custom_binary_name,
                passphrase,
                obfuscate,
                upx_path,
            )
            if agent_path:
                built_agents.append(agent_path)
    else:
        agent_path = builder.build_agent(
            arch,
            encryption,
            debug,
            custom_pipe_name,
            custom_binary_name,
            passphrase,
            obfuscate,
            upx_path,
        )
        if agent_path:
            built_agents.append(agent_path)

    return [str(path) for path in built_agents]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build polymorphic cooperative agents")
    parser.add_argument(
        "--arch",
        choices=["x86", "x64", "both"],
        default="both",
        help="Target architecture",
    )
    parser.add_argument(
        "--no-encryption",
        action="store_true",
        help="Disable polymorphic encryption",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    agents = build_cooperative_agent(
        arch=args.arch, encryption=not args.no_encryption, debug=args.debug
    )

    if agents:
        print(f"\nSuccessfully built {len(agents)} agent(s):")
        for agent in agents:
            print(f"  {agent}")
    else:
        print("No agents were built successfully")
        sys.exit(1)
