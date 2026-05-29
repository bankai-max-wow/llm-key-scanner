"""
Port scanner — no semaphore, no limits, just raw async gather per IP.
Scans only the highest-value LLM proxy ports for max throughput.
"""
import asyncio
import logging

logger = logging.getLogger(__name__)

# The ONLY ports worth scanning for LLM API key proxies
# 3000  = LiteLLM/NextJS default
# 8080  = Most common alt HTTP
# 8000  = Python/FastAPI
# 4000  = Phoenix/LiveView/panel hosts
# 7860  = HuggingFace/Gradio
TARGET_PORTS = [3000, 8080, 8000, 4000, 7860]


class PortScanner:
    """No semaphore, no limits — raw async TCP per IP."""

    def __init__(self, timeout: float = 0.8, ports: list[int] = None):
        self.timeout = timeout
        self.ports = ports or TARGET_PORTS

    async def _scan_one(self, ip: str, port: int) -> int | None:
        """Returns port if open, None otherwise."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionError, OSError):
            return None

    async def scan_ip(self, ip: str) -> list[int]:
        """Scan ALL ports on one IP in parallel. Returns open ports."""
        results = await asyncio.gather(*[self._scan_one(ip, p) for p in self.ports])
        return [p for p in results if p is not None]
