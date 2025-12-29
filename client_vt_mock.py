"""
Client script that calls the mock VirusTotal-like API.

Требования:
  pip install requests

Переменные окружения:
  VT_API_KEY   - API ключ (для mock-сервера подойдёт: test-key)
  VT_BASE_URL  - базовый URL API (по умолчанию: http://127.0.0.1:8000)

Запуск:
  1) В одном терминале:
       python mock_vt_server.py
  2) В другом терминале:
       export VT_API_KEY="test-key"
       python client_vt_mock.py 44d88612fea8a8f36de82e1278abb02f
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests


def get_env(name: str, default: str | None = None) -> str:
    val = os.getenv(name, default)
    if val is None or not str(val).strip():
        raise SystemExit(f"Missing required environment variable: {name}")
    return val


def fetch_file_report(base_url: str, api_key: str, file_id: str) -> Dict[str, Any]:
    """
    Делает запрос к mock API.

    "Авторизация" происходит через заголовок x-apikey, как в VirusTotal API.
    """
    url = f"{base_url.rstrip('/')}/api/v3/files/{file_id}"
    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    resp = requests.get(url, headers=headers, timeout=10)
    # На реальном API тут обычно обрабатывают 401/403/429 и т.д.
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python client_vt_mock.py <file_id>")

    file_id = sys.argv[1]
    api_key = get_env("VT_API_KEY")
    base_url = os.getenv("VT_BASE_URL", "http://127.0.0.1:8000")

    data = fetch_file_report(base_url, api_key, file_id)

    # Вывод в консоль (pretty JSON)
    print(json.dumps(data, ensure_ascii=False, indent=2))

    # Дополнительно можно сохранить в файл:
    out_path = f"vt_report_{file_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\nSaved to: {out_path}")


if __name__ == "__main__":
    main()