![ArpSpoof logo](https://mauricelambert.github.io/info/python/security/ArpSpoof_small.png "ArpSpoof logo")

# ArpSpoof

## Description

This package implements an ARP Spoofer for MIM (Man-In-the-Middle) or DoS (Denial of Service) attacks.

## Requirements

This package require:
 - python3
 - python3 Standard Library
 - Scapy
 - PythonToolsKit

## Installation

```bash
pip install ArpSpoof
```

## Usages

### Command lines

```bash
python3 -m ArpSpoof -h                    # Use python module
python3 ArpSpoof.pyz --help               # Use python executable

ArpSpoof 127.0.0.1 127.0.0.2              # Use console script entry point
ArpSpoof -v 127.0.0.1 127.0.0.2,127.0.0.5 # Spoof multiple targets (verbose mode)
ArpSpoof 127.0.0.1 127.0.0.2-127.0.0.5    # Spoof range of targets
ArpSpoof 127.0.0.1 127.0.0.0/29           # Spoof all network

ArpSpoof 127.0.0.1 127.0.0.0/29 -s -t 1   # Semi (spoof only gateway IP for the targets, interval is 1 seconds)
ArpSpoof 127.0.0.1 127.0.0.0/29 -i 127.0. # Use the loopback interface

ArpSpoof 172.16.10.1 172.16.0.33 -p       # Passive mode
```

### Python3

```python
from ArpSpoof import SpooferARP

spoofer = SpooferARP('172.16.10.1', '172.16.0.35')
spoofer.active_cache_poisonning()

spoofer = SpooferARP('172.16.10.1', '172.16.0.35', conf.iface, False, 0.5)
spoofer.passive_cache_poisonning(asynchronous=True)
spoofer.run = False
spoofer.sniffer.stop()                                   # only with asynchronous mode
spoofer.restore()                                        # only with asynchronous mode

# Multiple targets
spoofer = SpooferARP('127.0.0.1', '127.0.0.2,127.0.0.3') # Spoof multiple targets
spoofer = SpooferARP('127.0.0.1', '127.0.0.2-127.0.0.5') # Spoof range of targets
spoofer = SpooferARP('127.0.0.1', '127.0.0.0/30')        # Spoof all network
```

## Links

 - [Github Page](https://github.com/mauricelambert/ArpSpoof)
 - [Pypi](https://pypi.org/project/ArpSpoof/)
 - [Documentation](https://mauricelambert.github.io/info/python/security/ArpSpoof.html)
 - [Executable](https://mauricelambert.github.io/info/python/security/ArpSpoof.pyz)

## Help

```text
usage: ArpSpoof.py [-h] [--verbose] [--interface INTERFACE] [--time TIME] [--semi] [--passive] gateway target

positional arguments:
  gateway               Gateway IP or hostname
  target                Target IP or hostname

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Mode verbose (print debug message)
  --interface INTERFACE, -i INTERFACE
                        Part of the IP, MAC or name of the interface
  --time TIME, -t TIME  Time in seconds to sleep between sending ARP packets.
  --semi, -s            Spoof IP of the gateway (target will lost internet connection).
  --passive, -p         Passive mode (response to ARP request only)
```

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).