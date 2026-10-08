from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from wavs.core.crawler import CrawlResult


def make_handler(responder):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self._respond()

        def do_POST(self):
            self._respond()

        def _respond(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            parsed = urlparse(self.path)
            body, status, extra = responder(parsed.path, parse_qs(parsed.query))
            data = body.encode() if isinstance(body, str) else body
            headers = {"Content-Type": "text/html"}
            headers.update(extra or {})
            self.send_response(status)
            headers["Content-Length"] = str(len(data))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

    return Handler


@contextlib.contextmanager
def serve(responder):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(responder))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def crawl_result(urls):
    return CrawlResult(urls=list(urls), injection_points=[])
