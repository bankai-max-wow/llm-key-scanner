"""
IP Generator — generates random IPv4 addresses with smart targeting.
Biases toward cloud hosting ranges where people deploy LLM proxy services.
"""
import random
import ipaddress
from typing import Iterator

# High-density cloud / hosting ranges (CIDR blocks commonly used for web apps)
# These are weighted heavier for better hit rates
HIGH_VALUE_RANGES = [
    # AWS
    "3.0.0.0/8", "13.32.0.0/11", "13.48.0.0/12",
    "15.0.0.0/10", "16.0.0.0/8",
    "18.0.0.0/8", "35.0.0.0/8",
    "43.0.0.0/9", "44.0.0.0/10",
    # Google Cloud
    "8.0.0.0/9", "34.0.0.0/10", "35.184.0.0/13",
    "104.0.0.0/10", "107.0.0.0/8",
    # Azure
    "20.0.0.0/8", "40.0.0.0/10", "52.0.0.0/11",
    # DigitalOcean
    "64.0.0.0/11", "104.0.0.0/10", "159.0.0.0/8",
    # Hetzner
    "5.0.0.0/8", "49.0.0.0/9", "65.0.0.0/8",
    # OVH
    "51.0.0.0/8", "54.0.0.0/8", "141.0.0.0/8",
    # Vultr
    "45.0.0.0/8", "108.0.0.0/10",
    # Linode / Akamai
    "23.0.0.0/8", "96.0.0.0/10", "172.0.0.0/8",
    # Oracle Cloud
    "129.0.0.0/8", "130.0.0.0/8",
    # General hosting / colocation ranges
    "89.0.0.0/8", "91.0.0.0/8", "92.0.0.0/8",
    "93.0.0.0/8", "94.0.0.0/8", "95.0.0.0/8",
    "103.0.0.0/8", "104.0.0.0/8", "105.0.0.0/8",
    "106.0.0.0/8", "107.0.0.0/8",
    "109.0.0.0/8", "110.0.0.0/8",
    "111.0.0.0/8", "112.0.0.0/8", "113.0.0.0/8",
    "114.0.0.0/8", "115.0.0.0/8", "116.0.0.0/8",
    "117.0.0.0/8", "118.0.0.0/8", "119.0.0.0/8",
    "120.0.0.0/8", "121.0.0.0/8", "122.0.0.0/8",
    "123.0.0.0/8", "124.0.0.0/8", "125.0.0.0/8",
    "128.0.0.0/8", "129.0.0.0/8", "130.0.0.0/8",
    "131.0.0.0/8", "132.0.0.0/8", "133.0.0.0/8",
    "134.0.0.0/8", "135.0.0.0/8", "136.0.0.0/8",
    "137.0.0.0/8", "138.0.0.0/8", "139.0.0.0/8",
    "140.0.0.0/8", "141.0.0.0/8", "142.0.0.0/8",
    "143.0.0.0/8", "144.0.0.0/8", "145.0.0.0/8",
    "146.0.0.0/8", "147.0.0.0/8", "148.0.0.0/8",
    "149.0.0.0/8", "150.0.0.0/8", "151.0.0.0/8",
    "152.0.0.0/8", "153.0.0.0/8", "154.0.0.0/8",
    "155.0.0.0/8", "156.0.0.0/8", "157.0.0.0/8",
    "158.0.0.0/8", "159.0.0.0/8", "160.0.0.0/8",
    "161.0.0.0/8", "162.0.0.0/8", "163.0.0.0/8",
    "164.0.0.0/8", "165.0.0.0/8", "166.0.0.0/8",
    "167.0.0.0/8", "168.0.0.0/8", "169.0.0.0/8",
    "170.0.0.0/8", "171.0.0.0/8", "172.0.0.0/8",
    "173.0.0.0/8", "174.0.0.0/8", "175.0.0.0/8",
    "176.0.0.0/8", "177.0.0.0/8", "178.0.0.0/8",
    "179.0.0.0/8", "180.0.0.0/8", "181.0.0.0/8",
    "182.0.0.0/8", "183.0.0.0/8", "184.0.0.0/8",
    "185.0.0.0/8", "186.0.0.0/8", "187.0.0.0/8",
    "188.0.0.0/8", "189.0.0.0/8", "190.0.0.0/8",
    "191.0.0.0/8", "192.0.0.0/8", "193.0.0.0/8",
    "194.0.0.0/8", "195.0.0.0/8", "196.0.0.0/8",
    "197.0.0.0/8", "198.0.0.0/8", "199.0.0.0/8",
    "200.0.0.0/8", "201.0.0.0/8", "202.0.0.0/8",
    "203.0.0.0/8", "204.0.0.0/8", "205.0.0.0/8",
    "206.0.0.0/8", "207.0.0.0/8", "208.0.0.0/8",
    "209.0.0.0/8", "210.0.0.0/8", "211.0.0.0/8",
    "212.0.0.0/8", "213.0.0.0/8", "214.0.0.0/8",
    "215.0.0.0/8", "216.0.0.0/8", "217.0.0.0/8",
    "218.0.0.0/8", "219.0.0.0/8",
]

import struct

class IPGenerator:
    """Generates random IPv4 addresses with smart targeting."""

    def __init__(self, seed: int = None, high_value_weight: float = 0.7):
        self.rng = random.Random(seed)
        self.high_value_weight = high_value_weight
        self._high_value_pools = []
        for cidr in HIGH_VALUE_RANGES:
            net = ipaddress.IPv4Network(cidr, strict=False)
            self._high_value_pools.append(net)

    def _random_ip_in_net(self, net: ipaddress.IPv4Network) -> str:
        """Generate a random IP within a given network."""
        net_int = int(net.network_address)
        broadcast_int = int(net.broadcast_address)
        rand_int = self.rng.randint(net_int, broadcast_int)
        return str(ipaddress.IPv4Address(rand_int))

    def _random_global_ip(self) -> str:
        """Generate a purely random global IPv4 address."""
        while True:
            raw = self.rng.randint(0x01000000, 0xDFFFFFFF)
            ip_str = str(ipaddress.IPv4Address(raw))
            first_octet = raw >> 24
            # Skip reserved/private ranges
            if first_octet == 0 or first_octet >= 224:
                continue
            if (10 << 24) <= raw <= (10 << 24) + 0xFFFFFF:
                continue
            if (172 << 24) + (16 << 16) <= raw <= (172 << 24) + (31 << 16) + 0xFFFF:
                continue
            if (192 << 24) + (168 << 16) <= raw <= (192 << 24) + (168 << 16) + 0xFFFF:
                continue
            if ipaddress.IPv4Address(ip_str).is_private:
                continue
            if ipaddress.IPv4Address(ip_str).is_multicast:
                continue
            return ip_str

    def next_ip(self) -> str:
        """Get the next random IP to scan."""
        if self.rng.random() < self.high_value_weight and self._high_value_pools:
            pool = self.rng.choice(self._high_value_pools)
            return self._random_ip_in_net(pool)
        return self._random_global_ip()

    def batch_ips(self, count: int) -> list[str]:
        """Generate a batch of random IPs."""
        return [self.next_ip() for _ in range(count)]


def ip_generator(seed: int = None, high_value_weight: float = 0.7):
    """Convenience generator function."""
    gen = IPGenerator(seed, high_value_weight)
    while True:
        yield gen.next_ip()
