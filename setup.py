#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="byod-security-checker",
    version="1.0.0",
    author="saas.group",
    author_email="tech@saas.group",
    description="BYOD Security Compliance Checker for saas.group employees",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/saasgroup/byod-tool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "byod-tool=byod_security_check:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["google_signin.html"],
    },
)