from setuptools import setup, find_packages
from slinger import __version__
from slinger import __package__

def parse_requirements(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines() if line.strip()]

required_packages = parse_requirements('requirements.txt')

setup(
    name=__package__,
    version=__version__,
    packages=find_packages(),
    install_requires=required_packages,
    author="ghost-ng",
    author_email="ghost-ng@outlook.com",
    description="An impacket swiss army knife (sort of)",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ghost-ng/slinger",
    python_requires='>=3.10',
    # Add more parameters as needed
)
