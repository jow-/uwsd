#!/usr/bin/env python3
"""Shared raw-HTTP test harness helpers for uwsd."""

import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
BIN = os.environ.get("UWSD_BIN", str(ROOT / "build" / "uwsd"))
if not os.path.exists(BIN):
    BIN = str(ROOT / "uwsd")

TEXT_FILE = ROOT / "test.txt"


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class Server:
    def __init__(self, body, port):
        self.body = body
        self.port = port
        self.proc = None
        self.cfg = None

    def __enter__(self):
        self.cfg = tempfile.NamedTemporaryFile(
            prefix="uwsd-test-", suffix=".cfg", delete=False
        )
        self.cfg.write(self.body.encode())
        self.cfg.close()
        self.proc = subprocess.Popen(
            [BIN, "--config", self.cfg.name],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if not wait_port(self.port):
            self.__exit__(None, None, None)
            raise RuntimeError("uwsd did not start on port %d" % self.port)
        return self

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.cfg:
            os.unlink(self.cfg.name)


def read_response(sock, timeout=2.0):
    data = b""
    closed = False
    timedout = False
    sock.settimeout(timeout)
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            timedout = True
            break
        except (ConnectionResetError, BrokenPipeError):
            closed = True
            break
        if not chunk:
            closed = True
            break
        data += chunk
    return data, closed, timedout


def raw_request(port, payload, timeout=2.0, half_close=False):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(payload)
    if half_close:
        s.shutdown(socket.SHUT_WR)
    data, closed, timedout = read_response(s, timeout)
    s.close()
    return data, closed, timedout


def file_server(port, extra=""):
    return f"listen :{port} {{\n  {extra}\n  serve-file ./test.txt;\n}}\n"


def proxy_server(port, upstream_port):
    return f"listen :{port} {{\n  proxy-tcp 127.0.0.1:{upstream_port};\n}}\n"


class MockUpstream:
    def __init__(self, handler):
        self.port = free_port()
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(5)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = threading.Thread(target=self.handler, args=(conn,), daemon=True)
            t.start()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
