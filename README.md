# ArpSpoof

## Description
This package implement a ARP Spoofer (for MIM attack).

## Requirements
This package require :
 - python3
 - python3 Standard Library
 - Scapy

## Installation
```bash
pip install ArpSpoof
```

## Examples

### Command lines
```bash
ArpSpoof 192.168.1.1 192.168.1.2
ArpSpoof -s 192.168.1.1 192.168.1.2
```

### Python3
```python
from ArpSpoof import SpooferARP
SpooferARP("192.168.1.1", "192.168.1.2").launch()
SpooferARP("192.168.1.1", "192.168.1.2", semi = True, inter = 2.5).launch()
```

## Link
[Github Page](https://github.com/mauricelambert/ArpSpoof)

## Licence
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).