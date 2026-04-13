"""
SOCKS5 Proxy Builder for Slinger
Builds lightweight proxy binaries that tunnel traffic over named pipes.
Reuses the agent build pipeline (MinGW cross-compile, obfuscation, encryption).
"""

import os
import random
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from slingerpkg.lib.cooperative_agent import AgentBuilder
from slingerpkg.utils.printlib import *


class ProxyBuilder(AgentBuilder):
    """Builds SOCKS5 proxy binaries — inherits agent build pipeline."""

    # Proxy uses different source files than the agent
    PROXY_TEMPLATE_FILES = [
        "proxy_main.cpp",
        "socks_channel.h",
        "obfuscation.h",
        "pipe_core.h",
        "crypto.h",
        "dh_x25519.h",
        "auth_protocol.h",
    ]

    def __init__(self, base_path: str, debug: bool = False):
        super().__init__(base_path, debug)
        self.output_dir = Path.home() / ".slinger" / "proxies"

    def build_proxy(
        self,
        arch: str,
        custom_pipe_name: str = "slingproxy",
        passphrase: str = None,
        obfuscate: bool = False,
        upx_path: str = None,
        custom_binary_name: str = None,
        debug: bool = False,
    ) -> Optional[Path]:
        """Build SOCKS5 proxy binary for target architecture."""

        print_info(f"Building {arch} SOCKS proxy")
        if custom_pipe_name:
            print_info(f"  Pipe name: {custom_pipe_name}")
        if passphrase:
            print_info(f"  Authentication: ENABLED (passphrase-based encryption)")
        else:
            print_info(f"  Authentication: DISABLED (XOR encoding only)")
        if obfuscate:
            print_info(f"  Obfuscation: ENABLED")
        if debug:
            print_info(f"  Debug mode: ENABLED")
        if obfuscate and debug:
            print_warning("Debug mode adds plaintext strings — not recommended with --obfuscate")

        # Check build dependencies
        deps = self.check_build_dependencies()
        if not deps.get("cmake", False):
            print_bad("CMake not found. Install with: sudo apt install cmake build-essential")
            return None
        if not deps.get("cpp_compiler", False):
            print_bad("No C++ compiler found. Install MinGW cross-compiler.")
            return None

        # Generate polymorphic config
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
            # Copy and obfuscate template files (proxy-specific list)
            for template_file in self.PROXY_TEMPLATE_FILES:
                template_path = self.template_dir / template_file
                if template_path.exists():
                    obfuscated_content = self.apply_template_obfuscation(template_path, config)
                    output_path = build_path / template_file
                    with open(output_path, "w") as f:
                        f.write(obfuscated_content)
                else:
                    print_bad(f"Template file not found: {template_file}")
                    return None

            # Generate CMake config (proxy variant)
            self._generate_proxy_cmake(build_path, arch, config)

            # Configure
            configure_cmd = [
                "cmake",
                "-S",
                str(build_path),
                "-B",
                str(build_path / "build"),
                "-DCMAKE_BUILD_TYPE=Release",
            ]
            result = subprocess.run(
                configure_cmd, capture_output=True, text=True, cwd=str(build_path)
            )
            if result.returncode != 0:
                print_bad(f"CMake configure failed: {result.stderr}")
                return None

            # Build
            build_cmd = ["cmake", "--build", str(build_path / "build"), "--config", "Release"]
            result = subprocess.run(build_cmd, capture_output=True, text=True, cwd=str(build_path))
            if result.returncode != 0:
                print_bad(f"Build failed: {result.stderr}")
                return None

            # Find output binary
            build_id = config["build_id"]
            bin_dir = build_path / "build" / "bin"
            output_name = f"proxy_{build_id}.exe"
            output_binary = bin_dir / output_name

            if not output_binary.exists():
                # Try without .exe
                output_binary = bin_dir / f"proxy_{build_id}"
                if not output_binary.exists():
                    # Search for any exe in bin dir
                    for f in bin_dir.iterdir() if bin_dir.exists() else []:
                        if f.suffix in (".exe", "") and f.is_file():
                            output_binary = f
                            break

            if not output_binary.exists():
                print_bad(f"Build output not found in {bin_dir}")
                return None

            # Copy to output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)
            if custom_binary_name:
                final_name = custom_binary_name
                if not final_name.endswith(".exe"):
                    final_name += ".exe"
            else:
                final_name = f"proxy_{build_id}.exe"
                if obfuscate:
                    # Use a generic name when obfuscated
                    suffix = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=6))
                    final_name = f"svcproxy_{suffix}.exe"

            final_path = self.output_dir / final_name
            shutil.copy2(output_binary, final_path)

            file_size = final_path.stat().st_size
            print_good(f"Proxy built: {final_path}")
            print_info(f"  Size: {file_size:,} bytes ({file_size / 1024:.1f} KB)")
            print_info(f"  Arch: {arch}")
            print_info(f"  Pipe: {custom_pipe_name or '<random>'}")
            print_info(f"  Deploy: proxy deploy {final_path} --name <name> --start")

            # Save build info
            self._save_proxy_build_info(
                final_path, arch, config, custom_pipe_name, passphrase, file_size
            )

            return final_path

        except Exception as e:
            print_bad(f"Build failed: {e}")
            if debug:
                import traceback

                traceback.print_exc()
            return None

    def _generate_proxy_cmake(self, build_path, arch, config):
        """Generate CMake config for the proxy binary (not the agent)."""
        # Reuse the parent's generate_cmake_config but swap the target name and source file
        # We call super to get the cmake content, then replace agent references

        # Actually, easier to just generate it directly with the proxy target name
        if arch == "x86":
            compiler_prefix = "i686-w64-mingw32"
        else:
            compiler_prefix = "x86_64-w64-mingw32"

        build_id = config["build_id"]

        cmake = f"""
cmake_minimum_required(VERSION 3.15)
project(SlingerProxy_{build_id})

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER {compiler_prefix}-gcc)
set(CMAKE_CXX_COMPILER {compiler_prefix}-g++)
set(CMAKE_RC_COMPILER {compiler_prefix}-windres)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if("{arch}" STREQUAL "x64")
    add_definitions(-DARCH_X64)
elseif("{arch}" STREQUAL "x86")
    add_definitions(-DARCH_X86)
endif()

set(CMAKE_CXX_FLAGS "${{CMAKE_CXX_FLAGS}} -O3 -ffunction-sections -fdata-sections -fno-stack-protector")
set(CMAKE_EXE_LINKER_FLAGS "${{CMAKE_EXE_LINKER_FLAGS}} -Wl,--gc-sections -s -static -static-libgcc -static-libstdc++ -mwindows")
"""

        if config.get("obfuscate"):
            cmake += """
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fvisibility-inlines-hidden -fomit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--strip-debug -Wl,--no-export-dynamic -Wl,--exclude-libs,ALL")
add_definitions(-DNDEBUG -DNO_DEBUG_LOGS)
"""

        cmake += """
set(PLATFORM_LIBS kernel32 user32 advapi32 shell32 ws2_32 bcrypt)
"""

        cmake += f"""
add_definitions(
    -DBUILD_SEED={config['encryption_seed']}
    -DENCRYPTION_SEED={config['encryption_seed']}
    -DLAYOUT_SEED={config['layout_seed']}
    -DBUILD_ID="{build_id}"
)
"""

        if config.get("custom_pipe_name"):
            cmake += f'add_definitions(-DCUSTOM_PIPE_NAME="{config["custom_pipe_name"]}")\n'
        if config.get("debug_mode"):
            cmake += "add_definitions(-DDEBUG_MODE)\n"
        if config.get("passphrase"):
            cmake += f'add_definitions(-DAGENT_PASSPHRASE="{config["passphrase"]}")\n'

        cmake += f"""
add_executable(slinger_proxy_{build_id} proxy_main.cpp)
target_link_libraries(slinger_proxy_{build_id} PRIVATE ${{PLATFORM_LIBS}})
set_target_properties(slinger_proxy_{build_id} PROPERTIES
    OUTPUT_NAME "proxy_{build_id}"
    RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/bin"
)
"""

        if config.get("obfuscate"):
            cmake += f"""
add_custom_command(TARGET slinger_proxy_{build_id} POST_BUILD
    COMMAND ${{CMAKE_STRIP}} --strip-all --strip-unneeded $<TARGET_FILE:slinger_proxy_{build_id}>.exe
    COMMENT "Stripping symbols..."
)
"""

        if config.get("upx_path"):
            cmake += f"""
add_custom_command(TARGET slinger_proxy_{build_id} POST_BUILD
    COMMAND {config['upx_path']} --best --lzma --force $<TARGET_FILE:slinger_proxy_{build_id}>.exe
    COMMENT "Compressing with UPX..."
)
"""

        with open(build_path / "CMakeLists.txt", "w") as f:
            f.write(cmake)

    def _save_proxy_build_info(self, path, arch, config, pipe_name, passphrase, size):
        """Save proxy build metadata to registry."""
        import json
        import datetime

        registry_file = self.output_dir / "built_proxies.json"
        registry = []
        if registry_file.exists():
            try:
                with open(registry_file) as f:
                    registry = json.load(f)
            except Exception:
                registry = []

        entry = {
            "path": str(path),
            "filename": path.name,
            "arch": arch,
            "build_id": config["build_id"],
            "pipe_name": pipe_name,
            "auth_enabled": passphrase is not None,
            "passphrase": passphrase,
            "encryption_seed": config["encryption_seed"],
            "file_size": size,
            "built_at": datetime.datetime.now().isoformat(),
        }
        registry.append(entry)

        with open(registry_file, "w") as f:
            json.dump(registry, f, indent=2)
