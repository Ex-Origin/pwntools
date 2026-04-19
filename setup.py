"""Setup script for the minimal pwntools-compatible package."""

from pathlib import Path

from setuptools import find_packages, setup


here = Path(__file__).resolve().parent
long_description = (here / "README.md").read_text(encoding="utf-8")


setup(
    name="pwntools",
    version="0.1.0",
    description="Minimal pwntools-compatible toolkit for this testcase repo",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="windows-testcases contributors",
    license="MIT",
    packages=find_packages(),
    package_data={"pwn": ["*.pyi", "py.typed"]},
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="pwn, pwntools, exploit, ctf, windows, linux",
)
