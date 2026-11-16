"""最小 HTTP 转发代理 —— 给 codearts2api 的「出口代理」功能做真网验证。

职责：
- http:// 目标：绝对 URI 请求 → urllib 转发，响应加 `x-via-orkestr-proxy` 头；
- https:// 目标：CONNECT 隧道（字节透传，无法盖头，计数经 /hits 查询）；
- /hits / /ip：诊断端点（命中计数 / 本容器出口 IP）；
- 全部请求必须带 `x-proxy-token`（CONNECT 时查 Proxy-Authorization 头），
  防止公网上的开放代理被滥用。

 只用 Python 标准库。
"""

import base64
import json
import os
import socket
import select
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
TOKEN = os.environ.get("PROXY_TOKEN", "change-me")

hits = {"forward": 0, "connect": 0, "rejected": 0, "forward_error": 0}
lock = threading.Lock()


def bump(key):
    with lock:
        hits[key] += 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 安静模式：平台日志只留关键事件
        pass

    # -- 鉴权 -------------------------------------------------------------
    def _authorized(self):
        # 1) 显式头；2) http:// 代理场景下客户端可能用 Proxy-Authorization。
        if self.headers.get("x-proxy-token") == TOKEN:
            return True
        proxy_auth = self.headers.get("proxy-authorization")
        if proxy_auth and proxy_auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(proxy_auth.split(" ", 1)[1]).decode()
                user, _, password = decoded.partition(":")
                if password == TOKEN:
                    return True
            except Exception:
                pass
        return False

    def _reply(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("x-via-orkestr-proxy", "1")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    # -- http:// 绝对 URI 转发 --------------------------------------------
    def do_GET(self):
        if self.path.startswith("/hits"):
            self._reply(200, {"hits": hits, "token_ok": self._authorized()})
            return
        if self.path.startswith("/ip"):
            if not self._authorized():
                bump("rejected")
                self._reply(403, {"error": "bad token"})
                return
            try:
                ip = urllib.request.urlopen("https://api.ipify.org?format=json", timeout=15).read().decode()
                self._reply(200, json.loads(ip))
            except Exception as exc:
                self._reply(502, {"error": str(exc)})
            return
        if not self.path.startswith("http://"):
            self._reply(404, {"error": "send absolute-URI http:// or CONNECT", "path": self.path[:200]})
            return
        if not self._authorized():
            bump("rejected")
            self._reply(403, {"error": "bad token"})
            return
        bump("forward")
        try:
            request = urllib.request.Request(
                self.path,
                headers={k: v for k, v in self.headers.items() if k.lower() not in ("host", "proxy-authorization", "x-proxy-token")},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=25) as response:
                data = response.read()
                self.send_response(response.status)
                self.send_header("content-length", str(len(data)))
                self.send_header("x-via-orkestr-proxy", "1")
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            self.send_response(exc.code)
            self.send_header("content-length", str(len(data)))
            self.send_header("x-via-orkestr-proxy", "1")
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:
            bump("forward_error")
            self._reply(502, {"via": "orkestr-proxy", "error": f"{type(exc).__name__}: {exc}"})

    # -- https:// CONNECT 隧道 --------------------------------------------
    def do_CONNECT(self):
        if not self._authorized():
            bump("rejected")
            self._reply(403, {"error": "bad token"})
            return
        bump("connect")
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        try:
            remote = socket.create_connection((host, port), timeout=25)
        except Exception as exc:
            self._reply(502, {"via": "orkestr-proxy", "error": f"connect {host}:{port}: {exc}"})
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        conns = [self.connection, remote]
        try:
            while True:
                readable, _, _ = select.select(conns, [], [], 30)
                if not readable:
                    break  # 30s 无流量：收尾
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (remote if sock is self.connection else self.connection).sendall(data)
        except Exception:
            pass
        finally:
            remote.close()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"forward proxy on :{PORT}", flush=True)
    server.serve_forever()
