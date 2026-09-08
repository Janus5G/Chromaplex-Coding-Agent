from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

from .config import SERVICE_NAME


class CredentialStore:
    """Linux Secret Service storage with environment-variable fallback.

    Secrets are never written to QSettings, project files, logs or manifests.
    """

    ENV_NAMES = {
        "openai": "OPENAI_API_KEY",
        "caffeine": "CAFFEINE_API_KEY",
        "virustotal": "VIRUSTOTAL_API_KEY",
    }
    _session: dict[str, str] = {}

    @classmethod
    def get(cls, provider: str) -> Optional[str]:
        env_name = cls.ENV_NAMES.get(provider)
        if env_name:
            value = os.environ.get(env_name)
            if value:
                return value.strip()
        if provider in cls._session:
            return cls._session[provider]
        secret_tool = shutil.which("secret-tool")
        if not secret_tool:
            return None
        try:
            proc = subprocess.run(
                [secret_tool, "lookup", "application", SERVICE_NAME, "provider", provider],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception:
            return None
        return None

    @classmethod
    def set(cls, provider: str, secret: str) -> bool:
        cls._session[provider] = secret
        secret_tool = shutil.which("secret-tool")
        if not secret_tool:
            return False
        try:
            proc = subprocess.run(
                [
                    secret_tool,
                    "store",
                    "--label",
                    f"{SERVICE_NAME} {provider} API key",
                    "application",
                    SERVICE_NAME,
                    "provider",
                    provider,
                ],
                input=secret,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            return proc.returncode == 0
        except Exception:
            return False
