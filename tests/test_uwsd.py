#!/usr/bin/env python3
"""Raw-HTTP test suite for uwsd.

Run all tests:
    python3 tests/test_uwsd.py [UWSD_BIN]

Run one test:
    python3 tests/test_uwsd.py --test "empty chunk size" [UWSD_BIN]
"""

import argparse
import os
import socket
import sys
import time

import uwsd_harness as h

free_port = h.free_port
wait_port = h.wait_port
Server = h.Server
read_response = h.read_response
raw_request = h.raw_request
file_server = h.file_server
proxy_server = h.proxy_server
MockUpstream = h.MockUpstream

# ------------------------- tests -------------------------

def _mock_respond_200(c):
    c.recv(4096)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    c.close()


def test_empty_chunk_size():
    upstream = MockUpstream(_mock_respond_200)
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = (
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        # Secure: reject the empty chunk size; do not forward it upstream
        # and do not produce a successful response.
        ok = closed and b"200" not in data and b"405" not in data
        upstream.close()
        return ok, data[:160], closed, timedout


def test_extension_only_chunk_size():
    upstream = MockUpstream(_mock_respond_200)
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = (
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b";foo\r\n"
        )
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = closed and b"200" not in data and b"405" not in data
        upstream.close()
        return ok, data[:160], closed, timedout


def test_bare_lf_request():
    port = free_port()
    with Server(file_server(port), port):
        payload = b"GET / HTTP/1.1\nHost: x\n\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = (b"400" in data or closed) and b"200" not in data
        return ok, data[:160], closed, timedout


def test_te_and_content_length():
    port = free_port()
    with Server(file_server(port), port):
        payload = (
            b"POST / HTTP/1.1\r\nHost: x\r\n"
            b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
        )
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"400" in data and b"405" not in data
        return ok, data[:160], closed, timedout


def test_huge_chunk_size_pins():
    upstream = MockUpstream(lambda c: (time.sleep(5), c.close()))
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = (
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"FFFFFFFFFFFFFFFF\r\n"
        )
        data, closed, timedout = raw_request(port, payload, timeout=1.0)
        # Secure: reject/cap the chunk size promptly.
        ok = closed and b"405" not in data
        upstream.close()
        return ok, data[:160], closed, timedout


def test_negative_content_length():
    port = free_port()
    with Server(file_server(port), port):
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"400" in data and b"405" not in data
        return ok, data[:160], closed, timedout


def test_plus_content_length():
    port = free_port()
    with Server(file_server(port), port):
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +0\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"400" in data and b"405" not in data
        return ok, data[:160], closed, timedout


def test_nul_header_name():
    port = free_port()
    with Server(file_server(port), port):
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length\x00X: 0\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"400" in data and b"405" not in data
        return ok, data[:160], closed, timedout


def test_space_header_name():
    port = free_port()
    with Server(file_server(port), port):
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 0\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"400" in data and b"405" not in data
        return ok, data[:160], closed, timedout


def test_nul_header_value():
    port = free_port()
    with Server(file_server(port), port):
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\x00evil\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"400" in data and b"405" not in data
        return ok, data[:160], closed, timedout


def test_header_count_cap():
    port = free_port()
    headers = b"".join(b"X-%d: a\r\n" % i for i in range(101))
    with Server(file_server(port), port):
        payload = b"GET / HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"431" in data and b"200" not in data
        return ok, data[:160], closed, timedout


def test_header_bytes_cap():
    port = free_port()
    # > 16 KiB of headers but < 64 KiB total request head.
    headers = b"".join(b"X-%d: %s\r\n" % (i, b"a" * 200) for i in range(90))
    with Server(file_server(port), port):
        payload = b"GET / HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.5)
        ok = b"431" in data and b"200" not in data
        return ok, data[:160], closed, timedout


def test_incomplete_body_released():
    upstream = MockUpstream(lambda c: (time.sleep(5), c.close()))
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=1.0, half_close=True)
        # Secure: peer EOF with outstanding body closes promptly.
        ok = closed and not timedout
        upstream.close()
        return ok, data[:160], closed, timedout


def test_zero_chunk_before_body():
    def handler(c):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
        time.sleep(1.0)
        c.sendall(b"hello")
        time.sleep(0.5)
        c.close()

    upstream = MockUpstream(handler)
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=3.0)
        # Secure: no terminal chunk before the body.
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        first = body.split(b"\r\n", 1)[0] if body else b""
        ok = first != b"0" and body.count(b"0\r\n\r\n") == 1
        upstream.close()
        return ok, data[:400], closed, timedout


def test_1xx_interim_response():
    def handler(c):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        time.sleep(0.2)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello")
        c.close()

    upstream = MockUpstream(handler)
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=2.0)
        # Secure: skip 1xx and forward the final 200 response.
        ok = data.startswith(b"HTTP/1.1 200") and b"hello" in data
        upstream.close()
        return ok, data[:400], closed, timedout


def test_invalid_upstream_header():
    def handler(c):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nBadHeader\r\n\r\n")
        c.close()

    upstream = MockUpstream(handler)
    port = free_port()
    with Server(proxy_server(port, upstream.port), port):
        payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        data, closed, timedout = raw_request(port, payload, timeout=2.0)
        # Secure: malformed upstream header -> 502.
        ok = b"502" in data
        upstream.close()
        return ok, data[:400], closed, timedout


def test_connection_limit_delays_accept():
    port = free_port()
    cfg = (
        f"listen :{port} {{\n"
        f"  max-connections 1;\n"
        f"  serve-file ./test.txt;\n"
        f"}}\n"
    )
    with Server(cfg, port):
        first = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        first.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        d1, c1, t1 = read_response(first, timeout=1.0)
        assert b"200" in d1, d1

        second = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        second.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        d2, c2, t2 = read_response(second, timeout=1.0)
        # At the limit the listener is paused; the second connection is not
        # accepted and therefore not immediately closed.
        delayed = (not c2) and (b"200" not in d2)

        first.close()
        time.sleep(0.2)
        d2b, c2b, t2b = read_response(second, timeout=2.0)
        promoted = b"200" in d2b

        second.close()
        return (delayed and promoted), (d2[:80], d2b[:80]), c2, t2


def test_source_active_cap_does_not_affect_plain_files():
    def handler(c):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        time.sleep(3.0)
        c.close()

    upstream = MockUpstream(handler)
    port = free_port()
    cfg = (
        f"listen :{port} {{\n"
        f"  max-source-active-connections 1;\n"
        f"  match-path /proxy {{\n"
        f"    proxy-tcp 127.0.0.1:{upstream.port};\n"
        f"  }}\n"
        f"  match-path /file {{\n"
        f"    serve-file ./test.txt;\n"
        f"  }}\n"
        f"}}\n"
    )
    with Server(cfg, port):
        first = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        first.sendall(b"GET /proxy HTTP/1.1\r\nHost: x\r\n\r\n")
        d1, c1, t1 = read_response(first, timeout=1.0)
        assert b"200" in d1, d1

        second = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        second.sendall(b"GET /proxy HTTP/1.1\r\nHost: x\r\n\r\n")
        d2, c2, t2 = read_response(second, timeout=1.0)
        capped = b"429" in d2

        third = socket.create_connection(("127.0.0.1", port), timeout=1.0)
        third.sendall(b"GET /file HTTP/1.1\r\nHost: x\r\n\r\n")
        d3, c3, t3 = read_response(third, timeout=1.0)
        plain_ok = b"200" in d3

        first.close()
        second.close()
        third.close()
        upstream.close()
        return (capped and plain_ok), (d2[:120], d3[:120]), c2, t2


TESTS = {
    "empty chunk size": test_empty_chunk_size,
    "extension-only chunk size": test_extension_only_chunk_size,
    "bare LF request": test_bare_lf_request,
    "TE + Content-Length": test_te_and_content_length,
    "huge chunk size pins": test_huge_chunk_size_pins,
    "negative Content-Length": test_negative_content_length,
    "plus Content-Length": test_plus_content_length,
    "NUL header name": test_nul_header_name,
    "space header name": test_space_header_name,
    "NUL header value": test_nul_header_value,
    "header count cap": test_header_count_cap,
    "header bytes cap": test_header_bytes_cap,
    "incomplete body release": test_incomplete_body_released,
    "zero chunk before body": test_zero_chunk_before_body,
    "1xx interim response": test_1xx_interim_response,
    "invalid upstream header": test_invalid_upstream_header,
    "connection limit delays accept": test_connection_limit_delays_accept,
    "source active cap + plain files": test_source_active_cap_does_not_affect_plain_files,
}


def run_test(name, fn):
    try:
        ok, detail, closed, timedout = fn()
    except Exception as e:
        print(f"FAIL {name}: exception: {e}")
        return False

    if ok:
        print(f"PASS {name}")
        return True

    print(f"FAIL {name}: {detail!r} closed={closed} timedout={timedout}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Run uwsd raw-HTTP tests")
    parser.add_argument("--test", choices=sorted(TESTS))
    parser.add_argument("bin", nargs="?")
    args = parser.parse_args()

    if args.bin:
        h.BIN = args.bin

    if not os.path.exists(h.BIN):
        print("uwsd binary not found:", h.BIN)
        return 1

    if args.test:
        return 0 if run_test(args.test, TESTS[args.test]) else 1

    failed = 0
    for name, fn in TESTS.items():
        if not run_test(name, fn):
            failed += 1
    print(f"\n{failed} failed, {len(TESTS) - failed} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
