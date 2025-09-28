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

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.template_dir = self.base_path / "lib" / "agent_templates"
        self.build_dir = self.base_path / "build" / "agent"
        self.output_dir = self.base_path / "dist" / "agents"

        # Polymorphic encryption seeds
        self.encryption_seed = random.randint(1, 65535)
        self.layout_seed = random.randint(1000, 9999)

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

        return {
            "arch": arch,
            "encryption_seed": self.encryption_seed,
            "layout_seed": self.layout_seed,
            "function_mappings": func_mappings,
            "string_keys": string_keys,
            "build_id": f"{random.randint(10000, 99999)}_{arch}",
        }

    def apply_template_obfuscation(self, template_path: Path, config: Dict[str, Any]) -> str:
        """Apply obfuscation to template files"""

        with open(template_path, "r") as f:
            content = f.read()

        # Replace function name mappings
        for original, obfuscated in config["function_mappings"].items():
            content = content.replace(f"OBF_FUNC_NAME({original})", obfuscated)

        # Replace encryption seeds
        content = content.replace("BUILD_SEED", str(config["encryption_seed"]))
        content = content.replace("obf::compile_seed()", str(config["encryption_seed"]))

        # Add architecture-specific optimizations
        arch_defines = f"""
#define ARCH_{config['arch'].upper()}
#define BUILD_ID {config['build_id']}
#define LAYOUT_SEED {config['layout_seed']}
"""
        content = arch_defines + content

        return content

    def setup_build_environment(self, arch: str) -> Path:
        """Setup build environment for specific architecture"""

        build_path = self.build_dir / f"build_{arch}_{self.encryption_seed}"
        build_path.mkdir(parents=True, exist_ok=True)

        return build_path

    def generate_cmake_config(self, build_path: Path, arch: str, config: Dict[str, Any]) -> None:
        """Generate CMake configuration for polymorphic build"""

        cmake_content = f"""
cmake_minimum_required(VERSION 3.15)
project(SlingerAgent_{config['build_id']})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force architecture
if("{arch}" STREQUAL "x64")
    set(CMAKE_GENERATOR_PLATFORM x64)
    add_definitions(-DARCH_X64)
elseif("{arch}" STREQUAL "x86")
    set(CMAKE_GENERATOR_PLATFORM Win32)
    add_definitions(-DARCH_X86)
endif()

# Aggressive optimization and obfuscation
if(MSVC)
    set(CMAKE_CXX_FLAGS "${{CMAKE_CXX_FLAGS}} /O2 /Ob2 /GL /LTCG /GS- /Gy /Gw")
    set(CMAKE_EXE_LINKER_FLAGS
        "${{CMAKE_EXE_LINKER_FLAGS}} /LTCG /OPT:REF /OPT:ICF /SUBSYSTEM:WINDOWS")
elseif(MINGW OR CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS
        "${{CMAKE_CXX_FLAGS}} -O3 -ffunction-sections -fdata-sections -fno-stack-protector")
    set(CMAKE_EXE_LINKER_FLAGS "${{CMAKE_EXE_LINKER_FLAGS}} -Wl,--gc-sections -s -mwindows")
endif()

# Polymorphic definitions
add_definitions(
    -DENCRYPTION_SEED={config['encryption_seed']}
    -DLAYOUT_SEED={config['layout_seed']}
    -DBUILD_ID="{config['build_id']}"
)

# Source files
add_executable(slinger_agent_{config['build_id']}
    agent_main.cpp
)

# Windows libraries
target_link_libraries(slinger_agent_{config['build_id']} PRIVATE
    kernel32 user32 advapi32 shell32
)

# Output naming
set_target_properties(slinger_agent_{config['build_id']} PROPERTIES
    OUTPUT_NAME "agent_{config['build_id']}"
    RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin"
)
"""

        cmake_file = build_path / "CMakeLists.txt"
        with open(cmake_file, "w") as f:
            f.write(cmake_content)

    def build_agent(
        self, arch: str, encryption: bool = True, debug: bool = False
    ) -> Optional[Path]:
        """Build polymorphic agent for specific architecture"""

        print(f"Building {arch} agent with encryption: {encryption}")

        # Generate polymorphic configuration
        config = self.create_polymorphic_template(arch)

        # Setup build environment
        build_path = self.setup_build_environment(arch)

        try:
            # Copy and obfuscate template files
            template_files = [
                "agent_main.cpp",
                "obfuscation.h",
                "pipe_core.h",
                "command_executor.h",
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

            if arch == "x86":
                configure_cmd.extend(["-A", "Win32"])
            elif arch == "x64":
                configure_cmd.extend(["-A", "x64"])

            result = subprocess.run(configure_cmd, capture_output=True, text=True, cwd=build_path)
            if result.returncode != 0:
                print(f"CMake configure failed: {result.stderr}")
                return None

            # Build
            build_cmd = [
                "cmake",
                "--build",
                str(build_path / "build"),
                "--config",
                "Release",
                "--parallel",
            ]

            result = subprocess.run(build_cmd, capture_output=True, text=True, cwd=build_path)
            if result.returncode != 0:
                print(f"Build failed: {result.stderr}")
                return None

            # Find output executable
            output_pattern = f"agent_{config['build_id']}"
            bin_dir = build_path / "build" / "bin" / "Release"
            if not bin_dir.exists():
                bin_dir = build_path / "build" / "Release"

            for ext in [".exe", ""]:
                output_file = bin_dir / f"{output_pattern}{ext}"
                if output_file.exists():
                    # Copy to final output directory
                    self.output_dir.mkdir(parents=True, exist_ok=True)
                    final_output = self.output_dir / (
                        f"slinger_agent_{arch}_{config['encryption_seed']}.exe"
                    )
                    shutil.copy2(output_file, final_output)

                    print(f"Agent built successfully: {final_output}")
                    print(f"  Architecture: {arch}")
                    print(f"  Encryption seed: {config['encryption_seed']}")
                    print(f"  Build ID: {config['build_id']}")

                    return final_output

            print("Could not find built executable")
            return None

        except Exception as e:
            print(f"Build error: {e}")
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

        return {
            "template_dir": str(self.template_dir),
            "build_dir": str(self.build_dir),
            "output_dir": str(self.output_dir),
            "encryption_seed": self.encryption_seed,
            "layout_seed": self.layout_seed,
            "supported_architectures": ["x86", "x64"],
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


def build_cooperative_agent(
    arch: str = "both", encryption: bool = True, debug: bool = False
) -> List[str]:
    """
    Main function to build cooperative agents

    Args:
        arch: Architecture to build ('x86', 'x64', or 'both')
        encryption: Enable polymorphic encryption
        debug: Enable debug output

    Returns:
        List of built agent paths
    """

    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    builder = AgentBuilder(base_path)

    if debug:
        info = builder.get_build_info()
        print("Build Configuration:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        print()

    built_agents = []

    if arch == "both":
        built_agents = builder.build_all_architectures(encryption)
    else:
        agent_path = builder.build_agent(arch, encryption, debug)
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
