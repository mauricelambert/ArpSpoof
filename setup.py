from setuptools import setup

setup(
    name="ArpSpoof",
    version="1.1.2",
    py_modules=["ArpSpoof"],
    install_requires=["scapy", "PythonToolsKit"],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description="This package implements an ARP Spoofer for MIM (Man-In-the-Middle) or DoS (Denial of Service) attacks.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/ArpSpoof",
    project_urls={
        "Documentation": "https://mauricelambert.github.io/info/python/security/ArpSpoof.html",
        "Executable": "https://mauricelambert.github.io/info/python/security/ArpSpoof.pyz",
    },
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": ["ArpSpoof = ArpSpoof:main"],
    },
    keywords=[
        "ARP",
        "arpcachepoisonning",
        "arpcachepoison",
        "network",
        "ManInTheMiddle",
        "MIM",
        "Security",
        "DoS",
        "DenialOfService",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license="GPL-3.0 License",
)
