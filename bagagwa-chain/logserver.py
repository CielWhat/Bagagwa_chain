#!/usr/bin/env python3
"""Serves this folder over HTTP and saves PS5 beacon lines to server.log.

Usage:  python3 logserver.py [port, default 8000]
On PS5: open http://<this-mac-ip>:8000/index.html

notify.html sends one GET /log/<line> per event (only when not on
github.io and log != 0). Lines are printed and appended to server.log,
so SCAN-GADGET / SCAN-SYSCALL results survive even if you can't
select text on the console.
"""
import http.server
import urllib.parse
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # The PS5 browser caches by path and ignores query strings, which
        # caused stale-code ghosts. Force revalidation on every load.
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/log/"):
            line = urllib.parse.unquote(self.path[len("/log/"):])
            with open("server.log", "a") as f:
                f.write(line + "\n")
            print(line, flush=True)
            self.send_response(204)
            self.end_headers()
            return
        return super().do_GET()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"serving {PORT}, beacons -> server.log", flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
