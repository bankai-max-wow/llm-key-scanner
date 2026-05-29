"""
Port scanner — blazing-fast async TCP connect scanner.
Scans common web proxy ports where LLM API dashboards live.
"""
import asyncio
import logging
from typing import Callable, Awaitable

logger = logging.getLogger(__name__)

# The most common ports for LLM proxy dashboards, web UIs, and config panels
# Sorted by likelihood of finding something good
TARGET_PORTS = [
    3000,   # React dev / Node / Next.js / LiteLLM default
    3001,   # Alt UI port
    8080,   # Common alt HTTP
    8000,   # Python / FastAPI default
    80,     # HTTP
    443,    # HTTPS
    5000,   # Flask / Supabase
    7860,   # Hugging Face Spaces / Gradio
    9090,   # Prometheus / Cockpit
    8443,   # Alt HTTPS
    8888,   # Jupyter / common dev
    4000,   # Phoenix / Phoenix LiveView
    9000,   # Portainer / misc
    9443,   # Alt HTTPS
    3002,   # Alt
    3003,   # Alt
    8001,   # Alt
    8081,   # Alt
    9091,   # Alt
    5001,   # Alt Flask
    6000,   # X11 / misc
    7000,   # Misc
    7070,   # Real-time servers
    8082,   # Alt
    8880,   # Alt
    9444,   # Alt
    10000,  # NAT / webmin
    32400,  # Plex
    25565,  # Minecraft (surprisingly common for panel hosts)
    27015,  # SRCDS / game panels
    27016,  # Game panel alt
    2000,   # Cisco / misc
    2001,   # Cisco / misc
    2005,   # Misc
    2020,   # Misc
    2121,   # FTP alt
    3306,   # MySQL (rarely exposed but worth a shot)
    3389,   # RDP
    5800,   # VNC web
    5900,   # VNC
    5901,   # VNC alt
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    6443,   # Kubernetes API
    8444,   # Alt panel
    9042,   # Cassandra
    9100,   # Node exporter
    9200,   # Elasticsearch
    9300,   # Elasticsearch transport
    11211,  # Memcached
    27017,  # MongoDB
    50000,  # IBM DB2 / SAP
    50001,  # Alt
    50002,  # Alt
    50003,  # Alt
    49152,  # Windows dynamic
    49153,  # Windows dynamic
    49154,  # Windows dynamic
    49155,  # Windows dynamic
    49156,  # Windows dynamic
]

class PortScanner:
    """Async TCP connect port scanner."""

    def __init__(self, timeout: float = 1.0, max_concurrent: int = 2000):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def _scan_port(self, ip: str, port: int) -> tuple[str, int, bool]:
        """Check if a single port is open on an IP."""
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return ip, port, True
            except (asyncio.TimeoutError, ConnectionRefusedError,
                    ConnectionError, OSError):
                return ip, port, False

    async def scan_ip(self, ip: str, ports: list[int] = None) -> list[tuple[str, int]]:
        """Scan all target ports on a single IP. Returns list of (ip, port) open."""
        if ports is None:
            ports = TARGET_PORTS
        tasks = [self._scan_port(ip, p) for p in ports]
        results = await asyncio.gather(*tasks)
        open_ports = [(ip, port) for ip, port, status in results if status]
        return open_ports

    async def scan_ip_fast(self, ip: str) -> list[int]:
        """Return only open port numbers for a single IP."""
        results = await self.scan_ip(ip)
        return [port for _, port in results]

    async def scan_batch(
        self,
        ips: list[str],
        on_open: Callable[[str, int], Awaitable[None]] = None,
        ports: list[int] = None
    ) -> dict[str, list[int]]:
        """
        Scan multiple IPs. Returns dict of ip -> [open ports].
        Calls on_open(ip, port) callback if provided.
        """
        results = {}
        for ip in ips:
            open_ports = await self.scan_ip_fast(ip)
            if open_ports:
                results[ip] = open_ports
                if on_open:
                    for port in open_ports:
                        await on_open(ip, port)
        return results


# Quick standalone test
if __name__ == "__main__":
    async def test():
        scanner = PortScanner(timeout=1.0)
        open_ports = await scanner.scan_ip_fast("127.0.0.1")
        print(f"Open ports on localhost: {open_ports}")
    asyncio.run(test())
