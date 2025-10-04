import os
import socket
import sys
import threading
import time
import subprocess
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, HTTPServer

exe_path = "./build/http-client"

if len(sys.argv) > 1:
    exe_path = sys.argv[1]

if not os.path.exists(exe_path):
    print(f"file not exist: {exe_path}")
    sys.exit(1)

if not os.access(exe_path, os.X_OK):
    print(f"file is not executable: {exe_path}")
    sys.exit(1)

print(f"preparing tests for {exe_path}...")

tmpdir = "/tmp/network-check2"
serve_port = 8089
echo_port = 8082

def start_serve_server():
    global serve_server
    class ServeHandler(SimpleHTTPRequestHandler):
        def __init__(self, request, client_address, server):
            super().__init__(request, client_address, server, directory=tmpdir)
        def log_message(self, format, *args):
            pass
    serve_server = HTTPServer(("localhost", serve_port), ServeHandler)
    serve_server.address_family = socket.AF_INET6
    serve_server.serve_forever()
def stop_serve_server():
    global serve_server
    if serve_server:
        serve_server.shutdown()

def start_echo_server():
    global echo_server
    class EchoHandler(BaseHTTPRequestHandler):
        def _send_response(self, method, code = 200):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length > 0 else b""
            content = "\n".join([
                f"method = {method}.",
                f"path = {self.path}.",
                *[f"header = {k.lower()}: {v}." for k, v in  self.headers.items()],
                f"body = ",
            ]).encode("utf-8") + body + b"."

            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(content)
        def do_GET(self):
            self._send_response("GET")
        def do_POST(self):
            self._send_response("POST")
        def do_HEAD(self):
            self._send_response("HEAD")
        def do_PUT(self):
            self._send_response("PUT")
        def do_DELETE(self):
            self._send_response("DELETE")
        def do_SPAM(self):
            self._send_response("SPAM", code=501)
        def log_message(self, format, *args):
            pass
    echo_server = HTTPServer(("localhost", echo_port), EchoHandler)
    echo_server.address_family = socket.AF_INET6
    echo_server.serve_forever()
def stop_echo_server():
    global echo_server
    if echo_server:
        echo_server.shutdown()


def run(args, timeout=5):
    return subprocess.run(
        [exe_path, *args],
        capture_output=True,
        timeout=timeout,
    )

os.makedirs(tmpdir, exist_ok=True)
serve_thread = threading.Thread(target=start_serve_server, daemon=True)
serve_thread.start()
echo_thread = threading.Thread(target=start_echo_server, daemon=True)
echo_thread.start()
# wait for server ready
time.sleep(1)

tests = []

def it(name, fn):
    tests.append((name, fn))

def write(name, content):
    with open(f"{tmpdir}/{name}", "w", encoding="utf-8") as f:
        f.write(content)

# === tests ===

def test_should_work():
    write("check.txt", "it should works")
    res = run([f"http://127.0.0.1:{serve_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert res.stdout == b"it should works", "stdout should be response"
    # assert res.stderr == b"", "stderr should be empty"

it("should work", test_should_work)

def test_include_headers():
    write("check.txt", "header test")
    res = run(["-i", f"http://127.0.0.1:{serve_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"200 OK" in res.stdout, "should have 200 OK response header"
    assert b"Content-Length: 11" in res.stdout, "should have content-length header"
    assert b"header test" in res.stdout, "should have response body"

it("should include headers with -i", test_include_headers)

def test_should_send_get():
    res = run([f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = GET." in res.stdout, "request method should be GET"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "request should include correct Host header"
    assert b"body = ." in res.stdout, "request should include empty body"

it("should send GET request", test_should_send_get)

def test_should_send_post():
    res = run(["-X", "POST", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = POST." in res.stdout, "request method should be GET"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "request should include correct Host header"
    assert b"body = ." in res.stdout, "request should include empty body"

it("should send POST request", test_should_send_get)

def test_should_send_post_with_data():
    res = run(["-X", "POST", "-d", "114514", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = POST." in res.stdout, "request method should be POST"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "request should include correct Host header"
    assert f"header = content-length: 6.".encode() in res.stdout, "request should include correct Content-Length header"
    assert b"body = 114514." in res.stdout, "request should include correct body"

it("should send POST request with data", test_should_send_post_with_data)

def test_should_send_post_with_data_by_default():
    res = run(["-d", "114514", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = POST." in res.stdout, "request method should be POST"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "request should include correct Host header"
    assert b"body = 114514." in res.stdout, "request should include correct body"

it("should send POST request with data by default", test_should_send_post_with_data_by_default)

def test_post_with_custom_header():
    res = run([
        "-X", "POST",
        "-H", "X-Test: hello",
        f"http://127.0.0.1:{echo_port}/check.txt"
    ])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = POST." in res.stdout, "request method should be POST"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert b"header = x-test: hello." in res.stdout, "request should include X-Test header"
    assert b"body = ." in res.stdout, "request should include empty body"

it("should send POST request with custom header", test_post_with_custom_header)

def test_post_with_data_and_custom_header():
    res = run([
        "-X", "POST",
        "-d", "foobar",
        "-H", "X-Another: value",
        f"http://127.0.0.1:{echo_port}/check.txt"
    ])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = POST." in res.stdout, "request method should be POST"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert b"header = x-another: value." in res.stdout, "request should include X-Another header"
    assert b"body = foobar." in res.stdout, "request body should be 'foobar'"

it("should send POST request with data and custom header", test_post_with_data_and_custom_header)

def test_post_with_duplicated_headers():
    res = run([
        "-X", "POST",
        "-H", "X-Header: one",
        "-H", "X-Header: two",
        "-H", "X-Header: three",
        f"http://127.0.0.1:{echo_port}/"
    ])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = POST." in res.stdout, "request method should be POST"
    assert b"path = /." in res.stdout, "request path should be /"
    assert b"header = x-header: one." in res.stdout, "request should include multiple X-Header headers"
    assert b"header = x-header: two." in res.stdout, "request should include multiple X-Header headers"
    assert b"header = x-header: three." in res.stdout, "request should include multiple X-Header headers"
    assert b"body = ." in res.stdout, "request should include empty body"

it("should send POST request with duplicated custom header", test_post_with_duplicated_headers)

def test_should_send_put():
    res = run(["-X", "PUT", "-d", "putdata", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = PUT." in res.stdout, "request method should be PUT"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "request should include correct Host header"
    assert b"body = putdata." in res.stdout, "PUT request body should be 'putdata'"

it("should send PUT request", test_should_send_put)

def test_should_send_delete():
    res = run(["-X", "DELETE", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = DELETE." in res.stdout, "request method should be DELETE"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "request should include correct Host header"
    assert b"body = ." in res.stdout, "DELETE request body should be empty"

it("should send DELETE request", test_should_send_delete)

def test_should_send_custom_method():
    res = run(["-X", "SPAM", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"method = SPAM." in res.stdout, "request method should be SPAM"

it("should send custom method", test_should_send_custom_method)

def test_should_404():
    res = run([f"http://127.0.0.1:{serve_port}/notfound.txt"])
    assert res.returncode == 0, "return code should be 0 for 404"
    assert b"404" in res.stdout, "response should indicate 404 Not Found"

it("should return 404 for missing file", test_should_404)

# === URL parsing tests ===

def test_localhost_url():
    res = run([f"http://localhost:{echo_port}/check.txt"])
    assert res.returncode == 0, "return code should be 0"
    assert b"path = /check.txt." in res.stdout, "request path should be /check.txt"
    assert f"header = host: localhost:{echo_port}.".encode() in res.stdout, "Host header should be 'localhost:<port>'"

it("should handle localhost URL", test_localhost_url)

def test_url_with_query():
    res = run([f"http://127.0.0.1:{echo_port}/check.txt?param=value"])
    assert res.returncode == 0, "return code should be 0"
    assert b"path = /check.txt?param=value." in res.stdout, "request path should include query string"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "Host header should be correct"
    assert b"body = ." in res.stdout, "request body should be empty"

it("should handle URL with query string", test_url_with_query)

def test_url_with_hash():
    res = run([f"http://127.0.0.1:{echo_port}/check.txt#section"])
    assert res.returncode == 0, "return code should be 0"
    # fragment/hash should not be sent to server
    assert b"path = /check.txt." in res.stdout, "request path should ignore fragment/hash"
    assert b"#section" not in res.stdout, "fragment should not appear in request path"
    assert f"header = host: 127.0.0.1:{echo_port}.".encode() in res.stdout, "Host header should be correct"
    assert b"body = ." in res.stdout, "request body should be empty"

it("should ignore URL fragment/hash", test_url_with_hash)

def test_invalid_option():
    res = run(["-9", f"http://127.0.0.1:{echo_port}/check.txt"])
    assert res.returncode != 0, "return code should not be 0"

it("should error with invalid option", test_invalid_option)

def test_visit_example_com():
    res = run([f"http://example.com/"])
    assert res.returncode == 0, "return code should be 0"
    assert b"<h1>Example Domain</h1>" in res.stdout, "should have example domain in response"
    assert b"<!doctype html>" in res.stdout, "should have <!doctype html> in response"

it("should be ok visit http://example.com/", test_visit_example_com)

# =============

count_pass = 0
count_test = 0

print("")
print(f"running {len(tests)} tests")
start = time.perf_counter()

for name, fn in tests:
    print(f"test {name} ... ", end="")
    try:
        fn()
        print("\033[32mok\033[0m")
        count_pass += 1
        count_test += 1
    except Exception as e:
        print(f"\033[31mfail ({e})\033[0m")
        count_test += 1

print("")
end = time.perf_counter()
elapsed = end - start
print(f"test result: {"\033[32mok\033[0m" if count_pass == count_test else "\033[31mfail\033[0m"}. {count_pass} passed; {count_test - count_pass} failed; finished in {elapsed:.2f}s")

stop_serve_server()
stop_echo_server()
serve_thread.join()
echo_thread.join()
for entry in os.listdir(tmpdir):
    os.remove(os.path.join(tmpdir, entry))
os.rmdir(tmpdir)