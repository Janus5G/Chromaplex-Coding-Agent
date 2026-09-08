from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import CAFFEINE_CHAT_URL, OPENAI_RESPONSES_URL
from .modes import system_prompt


@dataclass
class GenerationResponse:
    text: str
    provider: str
    model: str


class AIClientError(RuntimeError):
    pass


def _post_json(url: str, payload: dict, api_key: str, timeout: int) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Chromaplex-Coding-Agent/0.4.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            details = json.loads(body)
            message = details.get("error", {}).get("message") or body
        except Exception:
            message = body
        raise AIClientError(f"API HTTP {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise AIClientError(f"Network/API error: {exc.reason}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AIClientError("API returned invalid JSON") from exc


def _extract_openai_text(data: dict) -> str:
    top = data.get("output_text")
    if isinstance(top, str) and top:
        return top
    pieces: list[str] = []
    for item in data.get("output", []) or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []) or []:
            if not isinstance(content, dict):
                continue
            if content.get("type") in {"output_text", "text"}:
                text = content.get("text")
                if isinstance(text, str):
                    pieces.append(text)
    if pieces:
        return "\n".join(pieces)
    raise AIClientError("OpenAI response contained no text output")


def strip_code_fence(text: str) -> str:
    stripped = text.strip()
    match = re.fullmatch(r"```[^\n]*\n(.*)\n```", stripped, re.DOTALL)
    return match.group(1).strip() if match else stripped


class AIAgent:
    def __init__(self, provider: str, api_key: str, model: str, timeout: int = 60):
        if provider not in {"openai", "caffeine"}:
            raise ValueError(f"Unknown provider: {provider}")
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.timeout = max(5, min(int(timeout), 600))

    def generate(self, user_prompt: str, mode: str, language: str, target: str | None = None) -> GenerationResponse:
        instructions = system_prompt(mode, language, target)
        if self.provider == "openai":
            data = _post_json(
                OPENAI_RESPONSES_URL,
                {"model": self.model, "instructions": instructions, "input": user_prompt},
                self.api_key,
                self.timeout,
            )
            text = _extract_openai_text(data)
        else:
            data = _post_json(
                CAFFEINE_CHAT_URL,
                {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": instructions},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.3,
                },
                self.api_key,
                self.timeout,
            )
            try:
                text = data["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as exc:
                raise AIClientError("Caffeine response contained no text output") from exc
        return GenerationResponse(strip_code_fence(text), self.provider, self.model)
