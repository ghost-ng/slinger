import re
import toml
from pathlib import Path
import subprocess


def get_package_dir():
    """Locate the main package directory dynamically."""
    src_path = Path(__file__).resolve().parent / "src"
    for package_dir in src_path.iterdir():
        if package_dir.is_dir() and (package_dir / "__init__.py").exists():
            return package_dir
    raise FileNotFoundError("Could not locate the main package directory containing __init__.py")


def get_version_from_init(package_dir):
    """Extract the version from the top-level __init__.py file."""
    init_file = package_dir / "__init__.py"
    version_pattern = r"^__version__\s*=\s*['\"]([^'\"]+)['\"]"
    with open(init_file, "r") as f:
        for line in f:
            match = re.match(version_pattern, line)
            if match:
                return match.group(1)
    raise ValueError("Version not found in __init__.py")


def update_version_in_init(package_dir, new_version):
    """Update the version in the top-level __init__.py file."""
    init_file = package_dir / "__init__.py"
    version_pattern = r"(^__version__\s*=\s*)['\"][^'\"]+['\"]"
    with open(init_file, "r") as f:
        content = f.read()
    updated_content = re.sub(version_pattern, fr"\1'{new_version}'", content)
    with open(init_file, "w") as f:
        f.write(updated_content)
    print(f"Updated version in {init_file} to {new_version}")


def get_version_from_pyproject(pyproject_file):
    """Extract the version from pyproject.toml."""
    pyproject_data = toml.load(pyproject_file)
    return pyproject_data.get("project", {}).get("version")


def update_version_in_pyproject(pyproject_file, new_version):
    """Update the version in pyproject.toml."""
    pyproject_data = toml.load(pyproject_file)
    if "project" in pyproject_data and "version" in pyproject_data["project"]:
        pyproject_data["project"]["version"] = new_version
        with open(pyproject_file, "w") as f:
            toml.dump(pyproject_data, f)
        print(f"Updated version in {pyproject_file} to {new_version}")


def run_build():
    """Run the Python build process."""
    try:
        # Ensure `build` is installed
        subprocess.run(["pip", "install", "--upgrade", "build"], check=True)

        # Run the build command
        subprocess.run(["python", "-m", "build"], check=True)
        print("Build completed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
    except FileNotFoundError:
        print("Ensure that Python and the `build` module are installed.")


def main():
    # Locate necessary files
    current_dir = Path(__file__).resolve().parent
    pyproject_file = current_dir / "pyproject.toml"
    package_dir = get_package_dir()

    # Get versions from pyproject.toml and __init__.py
    pyproject_version = get_version_from_pyproject(pyproject_file)
    init_version = get_version_from_init(package_dir)

    print(f"Current version in pyproject.toml: {pyproject_version}")
    print(f"Current version in __init__.py: {init_version}")

    # Decide the new version (for simplicity, assume pyproject.toml is the source of truth)
    new_version = pyproject_version

    # Update the version in __init__.py if it doesn't match
    if init_version != new_version:
        update_version_in_init(package_dir, new_version)

    # Update the version in pyproject.toml if it doesn't match
    if pyproject_version != init_version:
        update_version_in_pyproject(pyproject_file, new_version)

    # Run the build process
    run_build()


if __name__ == "__main__":
    main()
