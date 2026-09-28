from __future__ import annotations

import json
import logging
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import QTYPE, RR, A, DNSHeader, DNSRecord

LOG = logging.getLogger(__name__)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        request = DNSRecord.parse(data)
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=30))
        sock.sendto(reply.pack(), self.client_address)


class HTTPHandler(BaseHTTPRequestHandler):
    server_version = "IDSMLLab/0.1"

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        LOG.debug(format, *args)


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    dns_server = socketserver.ThreadingUDPServer(("0.0.0.0", 5353), DNSHandler)
    dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
    dns_thread.start()
    LOG.info("DNS lab service listening on UDP 5353")
    http_server = ThreadingHTTPServer(("0.0.0.0", 8080), HTTPHandler)
    LOG.info("HTTP lab service listening on TCP 8080")
    try:
        http_server.serve_forever()
    finally:
        dns_server.shutdown()


if __name__ == "__main__":
    main()
