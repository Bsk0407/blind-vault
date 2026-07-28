#!/usr/bin/env python3
"""Zero-dependency integration tests for the local Windows dashboard."""

from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent
UI_SCRIPT = ROOT / "ui" / "vault_ui.py"
VAULT_SCRIPT = ROOT / "bin" / "vault.ps1"


def check(condition: bool, message: str, counter: list[int]) -> None:
    if not condition:
        raise AssertionError(message)
    counter[0] += 1


def request(
    port: int,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict | None = None,
) -> tuple[int, dict[str, str], str]:
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = dict(headers or {})
    if encoded is not None:
        request_headers["Content-Type"] = "application/json"
        request_headers["Content-Length"] = str(len(encoded))
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=encoded, headers=request_headers)
        response = connection.getresponse()
        text = response.read().decode("utf-8", errors="replace")
        return response.status, {key.lower(): value for key, value in response.getheaders()}, text
    finally:
        connection.close()


def main() -> None:
    if os.name != "nt":
        raise SystemExit("Windows UI tests require native Windows")

    assertions = [0]
    name = "ui-test-" + uuid.uuid4().hex
    secret = "ui-secret-" + uuid.uuid4().hex
    added = False
    removed = False
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    with tempfile.TemporaryDirectory(prefix="blind-vault-ui-test-") as test_dir:
        env = os.environ.copy()
        env.update(
            {
                "BLINDVAULT_DIR": test_dir,
                "BLINDVAULT_UI_NO_OPEN": "1",
                "PYTHONUNBUFFERED": "1",
            }
        )
        server = subprocess.Popen(
            [sys.executable, "-u", str(UI_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=creationflags,
        )
        try:
            line = server.stdout.readline() if server.stdout else ""
            match = re.search(r"(http://127\.0\.0\.1:(\d+)/)", line)
            if not match:
                error = server.stderr.read() if server.stderr else ""
                raise RuntimeError("dashboard did not start: " + error[:300])
            origin = match.group(1).rstrip("/")
            port = int(match.group(2))

            status, headers, page = request(port, "GET", "/")
            check(status == 200, "root page loads", assertions)
            check("no-store" in headers.get("cache-control", ""), "root is not cached", assertions)
            check("default-src 'none'" in headers.get("content-security-policy", ""), "CSP is present", assertions)
            check('type="password"' in page, "page contains a masked secret input", assertions)
            token_match = re.search(r'const TOKEN = "([a-f0-9]+)";', page)
            check(token_match is not None, "page contains a per-session token", assertions)
            token = token_match.group(1)

            evil_status, _, evil_body = request(
                port, "GET", "/", headers={"Host": "127.0.0.1.evil"}
            )
            check(evil_status == 403, "prefix Host attack is blocked", assertions)
            check(token not in evil_body, "forbidden Host response does not disclose token", assertions)

            no_token_status, _, _ = request(port, "GET", "/api/list")
            check(no_token_status == 403, "API requires the session token", assertions)

            api_headers = {"X-Vault-Token": token, "Origin": origin}
            status, _, body = request(port, "GET", "/api/list", headers=api_headers)
            check(status == 200 and json.loads(body).get("secrets") == [], "authorized list starts empty", assertions)

            missing_origin_status, _, _ = request(
                port,
                "POST",
                "/api/add",
                headers={"X-Vault-Token": token},
                body={"name": name, "value": secret},
            )
            check(missing_origin_status == 403, "POST requires an exact local Origin", assertions)

            wrong_origin_status, _, _ = request(
                port,
                "POST",
                "/api/add",
                headers={"X-Vault-Token": token, "Origin": "http://localhost.evil"},
                body={"name": name, "value": secret},
            )
            check(wrong_origin_status == 403, "cross-origin POST is blocked", assertions)

            status, _, add_body = request(
                port,
                "POST",
                "/api/add",
                headers=api_headers,
                body={
                    "name": name,
                    "value": secret,
                    "service": "UI Test",
                    "env": "BV_UI_TEST",
                    "allow": "powershell.exe",
                },
            )
            check(status == 200 and json.loads(add_body).get("ok") is True, "dashboard adds a credential", assertions)
            added = True
            check(secret not in add_body, "add response does not contain the value", assertions)

            status, _, list_body = request(port, "GET", "/api/list", headers=api_headers)
            check(status == 200 and name in list_body, "pointer appears in list", assertions)
            check(secret not in list_body, "list response does not contain the value", assertions)

            oversize_status, _, oversize_body = request(
                port,
                "POST",
                "/api/add",
                headers=api_headers,
                body={"name": "oversize-" + uuid.uuid4().hex, "value": "x" * 2561},
            )
            check(oversize_status == 400, "dashboard enforces the WinCred byte limit", assertions)
            check("x" * 64 not in oversize_body, "oversize response does not echo the value", assertions)

            status, _, remove_body = request(
                port, "POST", "/api/rm", headers=api_headers, body={"name": name}
            )
            check(status == 200 and json.loads(remove_body).get("ok") is True, "dashboard removes the credential", assertions)
            removed = True

            status, _, final_list = request(port, "GET", "/api/list", headers=api_headers)
            check(status == 200 and name not in final_list, "pointer is removed from the list", assertions)
            print(f"PASS: {assertions[0]} Windows dashboard assertions")
        finally:
            if added and not removed:
                subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(VAULT_SCRIPT),
                        "rm",
                        name,
                    ],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    creationflags=creationflags,
                    check=False,
                )
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    main()

