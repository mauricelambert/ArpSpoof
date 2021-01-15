from setuptools import setup, find_packages

setup(
    name = 'ArpSpoof',
 
    version = "0.0.1",
    packages = find_packages(include=["ArpSpoof"]),
    install_requires = ['scapy'],

    author = "Maurice Lambert", 
    author_email = "mauricelambert434@gmail.com",
 
    description = "This package implement a ARP Spoofer (for MIM attack).",
    long_description = open('README.md').read(),
    long_description_content_type="text/markdown",
 
    include_package_data = True,

    url = 'https://github.com/mauricelambert/ArpSpoof',
 
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8"
    ],
 
    entry_points = {
        'console_scripts': [
            'ArpSpoof = ArpSpoof:arpspoofer'
        ],
    },
    python_requires='>=3.6',
)