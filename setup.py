from setuptools import setup, find_packages

setup(
    name="av-pvd",
    version="0.1.0",
    description="Adaptive Vulnerability Propagation Detection for Ethereum",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[],
    extras_require={
        "live": ["web3>=6.11"],
        "plot": ["matplotlib>=3.7", "pandas>=2.0"],
        "dev": ["pytest>=7.0"],
    },
)
