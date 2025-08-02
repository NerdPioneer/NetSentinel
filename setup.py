"""
NetSentinel Setup Configuration

This file defines the package setup for NetSentinel,
allowing it to be installed as a Python package.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="netsentinel",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A modular Python project for network traffic analysis and threat detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/NetSentinel",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.2.0",
            "pytest-cov>=2.12.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
        ],
        "geo": [
            "maxminddb>=2.2.0",
            "geoip2>=4.6.0",
        ],
        "ml": [
            "scikit-learn>=1.0.0",
            "numpy>=1.21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netsentinel=netsentinel.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "netsentinel": ["*.yaml", "*.json"],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourusername/NetSentinel/issues",
        "Source": "https://github.com/yourusername/NetSentinel",
        "Documentation": "https://github.com/yourusername/NetSentinel/docs",
    },
)
