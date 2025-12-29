
"""
Mock VirusTotal-like API server.

Запуск:
  python mock_vt_server.py

Сервер поднимется на:
  http://127.0.0.1:8000

Эндпоинты:
  GET /api/v3/files/<file_id>

"Авторизация":
  Ожидается заголовок: x-apikey: <YOUR_KEY>
  (ключ можно любой, например "test-key")

Пример:
  curl -H "x-apikey: test-key" http://127.0.0.1:8000/api/v3/files/44d88612fea8a8f36de82e1278abb02f
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


HOST = "127.0.0.1"
PORT = 8000

# Можно хранить "валидные" ключи тут (для демонстрации)
VALID_API_KEYS = {"test-key", "demo-key"}


def vt_like_response(file_id: str) -> dict:
    """Собираем VT-подобный JSON-ответ."""
    return {
        "data": {
            "type": "file",
            "id": file_id,
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 62,
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 8,
                    "timeout": 0,
                },
                "meaningful_name": "example.bin",
                "sha256": file_id,
                "last_analysis_date": 1735440000,  # пример unix time
            },
        },
        "meta": {
            "mock": True,
            "note": "This is a mocked VirusTotal-like response.",
        },
    }


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        api_key = self.headers.get("x-apikey")
        if not api_key:
            return self._send_json(
                401,
                {"error": {"code": "NotAuthorized", "message": "Missing x-apikey header"}, "mock": True},
            )
        if api_key not in VALID_API_KEYS:
            return self._send_json(
                403,
                {"error": {"code": "Forbidden", "message": "Invalid API key"}, "mock": True},
            )

        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "v3" and parts[2] == "files":
            file_id = parts[3]
            return self._send_json(200, vt_like_response(file_id))

        return self._send_json(
            404,
            {"error": {"code": "NotFound", "message": f"Unknown endpoint: {path}"}, "mock": True},
        )

    # Чтобы не шуметь стандартными логами
    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> None:
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Mock server running: http://{HOST}:{PORT}")
    print("Try: GET /api/v3/files/<file_id> with header x-apikey")
    server.serve_forever()


if __name__ == "__main__":
    main()
