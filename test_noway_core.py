import socket
import threading
import unittest

from ZainWolfTunnel import LocalHttpProxyServer, LocalSocksServer

from noway_core import (
    DEFAULT_PAYLOAD,
    build_payload,
    open_http_proxy_tunnel,
    open_socks5_proxy_tunnel,
    parse_host_port,
    parse_server_spec,
)


def recv_until(sock, marker=b"\r\n\r\n"):
    data = bytearray()
    while not data.endswith(marker):
        b = sock.recv(1)
        if not b:
            break
        data.extend(b)
    return bytes(data)


class CoreTests(unittest.TestCase):
    def test_parse_server_spec_password_may_contain_colons_and_at(self):
        self.assertEqual(
            parse_server_spec("ssh.example.net:443@myuser:pass:word@tail"),
            ("ssh.example.net", 443, "myuser", "pass:word@tail"),
        )

    def test_parse_server_spec_ipv6(self):
        self.assertEqual(parse_server_spec("[2001:db8::5]:22@user:secret"),
                         ("2001:db8::5", 22, "user", "secret"))

    def test_invalid_server_spec(self):
        with self.assertRaises(ValueError):
            parse_server_spec("not-a-valid-account")
        with self.assertRaises(ValueError):
            parse_server_spec("host:70000@u:p")

    def test_parse_proxy_endpoint(self):
        self.assertEqual(parse_host_port("proxy.example.net:8080"), ("proxy.example.net", 8080))
        self.assertEqual(parse_host_port("[::1]:1080"), ("::1", 1080))

    def test_payload_replacement(self):
        actual = build_payload(DEFAULT_PAYLOAD, "ssh.example.net", 443)
        self.assertEqual(actual, b"CONNECT ssh.example.net:443 HTTP/1.1\r\nHost: ssh.example.net:443\r\nProxy-Connection: Keep-Alive\r\n\r\n")
        self.assertEqual(build_payload("[netData][crlf][crlf]", "host.test", 22),
                         b"CONNECT host.test:22 HTTP/1.1\r\n\r\n")

    def test_http_proxy_handshake_integration(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        received = {}

        def fake_proxy():
            conn, _ = listener.accept()
            with conn:
                received["payload"] = recv_until(conn)
                conn.sendall(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n")
                received["next"] = conn.recv(4)
            listener.close()

        thread = threading.Thread(target=fake_proxy, daemon=True)
        thread.start()
        tunneled = open_http_proxy_tunnel("127.0.0.1", port, "ssh.example.net", 443, DEFAULT_PAYLOAD)
        tunneled.sendall(b"PING")
        tunneled.close()
        thread.join(timeout=3)
        self.assertIn(b"CONNECT ssh.example.net:443 HTTP/1.1", received["payload"])
        self.assertEqual(received["next"], b"PING")

    def test_http_proxy_handles_redirect_switch_and_tunnel_responses(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        captured = {}

        def fake_proxy():
            conn, _ = listener.accept()
            with conn:
                captured["payload"] = recv_until(conn)
                conn.sendall(
                    b"HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nLocation: /cdn-cgi/\r\n\r\n"
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n"
                    b"SSH-2.0-OpenSSH_9.0 test\r\n"
                )
                captured["after_handshake"] = conn.recv(4)
            listener.close()

        thread = threading.Thread(target=fake_proxy, daemon=True)
        thread.start()
        statuses = []
        payload = "GET /cdn-cgi HTTP/1.1[crlf]Host: test.invalid[crlf][crlf]"
        tunnel = open_http_proxy_tunnel(
            "127.0.0.1", port, "ssh.example.net", 443, payload,
            status_callback=statuses.append,
        )
        try:
            self.assertEqual(recv_until(tunnel, b"\r\n"), b"SSH-2.0-OpenSSH_9.0 test\r\n")
            tunnel.sendall(b"PING")
        finally:
            tunnel.close()
        thread.join(timeout=3)
        self.assertIn(b"GET /cdn-cgi HTTP/1.1", captured["payload"])
        self.assertEqual([line.split()[1] for line in statuses], ["301", "101", "200"])
        self.assertEqual(captured["after_handshake"], b"PING")

    def test_http_proxy_rejection(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def fake_proxy():
            conn, _ = listener.accept()
            with conn:
                recv_until(conn)
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            listener.close()

        threading.Thread(target=fake_proxy, daemon=True).start()
        with self.assertRaisesRegex(OSError, "403"):
            open_http_proxy_tunnel("127.0.0.1", port, "ssh.example.net", 443, DEFAULT_PAYLOAD)

    def test_socks5_proxy_handshake_integration(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        got_request = {}

        def fake_socks():
            conn, _ = listener.accept()
            with conn:
                got_request["methods"] = conn.recv(3)
                conn.sendall(b"\x05\x00")
                hdr = conn.recv(5)
                addr_len = hdr[4]
                host = conn.recv(addr_len)
                dst_port = conn.recv(2)
                got_request["target"] = (host.decode(), int.from_bytes(dst_port, "big"))
                conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
                got_request["ping"] = conn.recv(4)
            listener.close()

        thread = threading.Thread(target=fake_socks, daemon=True)
        thread.start()
        tunnel = open_socks5_proxy_tunnel("127.0.0.1", port, "ssh.example.net", 443)
        tunnel.sendall(b"PING")
        tunnel.close()
        thread.join(timeout=3)
        self.assertEqual(got_request["methods"], b"\x05\x01\x00")
        self.assertEqual(got_request["target"], ("ssh.example.net", 443))
        self.assertEqual(got_request["ping"], b"PING")

    def test_local_socks5_server_forwards_over_fake_ssh_channel(self):
        class FakeTransport:
            def is_active(self):
                return True

            def open_channel(self, kind, destination, source, timeout=15):
                self.destination = destination
                local_end, remote_end = socket.socketpair()

                def echo():
                    with remote_end:
                        try:
                            while True:
                                data = remote_end.recv(1024)
                                if not data:
                                    return
                                remote_end.sendall(b"echo:" + data)
                        except OSError:
                            return

                threading.Thread(target=echo, daemon=True).start()
                return local_end

        transport = FakeTransport()
        server = LocalSocksServer(transport, "127.0.0.1", 0)
        port = server.listener.getsockname()[1]
        server.start()
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x00")
            self.assertEqual(client.recv(2), b"\x05\x00")
            host = b"example.test"
            request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (443).to_bytes(2, "big")
            client.sendall(request)
            self.assertEqual(client.recv(10), b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.sendall(b"PING")
            self.assertEqual(client.recv(9), b"echo:PING")
            self.assertEqual(transport.destination, ("example.test", 443))
        finally:
            client.close()
            server.close()

    def test_local_http_proxy_connect_forwards_over_ssh(self):
        class FakeTransport:
            def __init__(self):
                self.destination = None

            def is_active(self):
                return True

            def open_channel(self, kind, destination, source, timeout=15):
                self.destination = destination
                local_end, remote_end = socket.socketpair()

                def echo():
                    with remote_end:
                        try:
                            while True:
                                data = remote_end.recv(2048)
                                if not data:
                                    return
                                remote_end.sendall(b"echo:" + data)
                        except OSError:
                            return

                threading.Thread(target=echo, daemon=True).start()
                return local_end

        transport = FakeTransport()
        server = LocalHttpProxyServer(transport, "127.0.0.1", 0)
        port = server.listener.getsockname()[1]
        server.start()
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            client.settimeout(2)
            client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
            response = recv_until(client)
            self.assertIn(b"200 Connection Established", response)
            self.assertEqual(transport.destination, ("example.test", 443))
            client.sendall(b"PING")
            self.assertEqual(client.recv(9), b"echo:PING")
        finally:
            client.close()
            server.close()

    def test_local_http_proxy_rewrites_absolute_http_url(self):
        class FakeTransport:
            def __init__(self):
                self.destination = None

            def is_active(self):
                return True

            def open_channel(self, kind, destination, source, timeout=15):
                self.destination = destination
                local_end, remote_end = socket.socketpair()

                def echo():
                    with remote_end:
                        try:
                            while True:
                                data = remote_end.recv(4096)
                                if not data:
                                    return
                                remote_end.sendall(data)
                        except OSError:
                            return

                threading.Thread(target=echo, daemon=True).start()
                return local_end

        transport = FakeTransport()
        server = LocalHttpProxyServer(transport, "127.0.0.1", 0)
        port = server.listener.getsockname()[1]
        server.start()
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            client.settimeout(2)
            client.sendall(b"GET http://example.test/path?q=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Connection: keep-alive\r\n\r\n")
            response = recv_until(client)
            self.assertTrue(response.startswith(b"GET /path?q=1 HTTP/1.1\r\n"), response)
            self.assertNotIn(b"Proxy-Connection", response)
            self.assertIn(b"Connection: close", response)
            self.assertEqual(transport.destination, ("example.test", 80))
        finally:
            client.close()
            server.close()

    def test_relay_supports_paramiko_style_channel_without_selecting_channel_fd(self):
        import select

        class FakeParamikoChannel:
            def __init__(self, sock):
                self.sock = sock
                self.closed = False
                self.eof_received = False

            def fileno(self):
                # Mimic a channel whose descriptor is not a Winsock socket.
                raise OSError("not a selectable Windows socket")

            def recv_ready(self):
                return bool(select.select([self.sock], [], [], 0)[0])

            def recv(self, size):
                return self.sock.recv(size)

            def sendall(self, data):
                self.sock.sendall(data)

            def shutdown_write(self):
                self.sock.shutdown(socket.SHUT_WR)

            def close(self):
                self.closed = True
                self.sock.close()

        class FakeTransport:
            def is_active(self):
                return True

            def open_channel(self, kind, destination, source, timeout=15):
                local_end, remote_end = socket.socketpair()
                channel = FakeParamikoChannel(local_end)

                def echo():
                    with remote_end:
                        try:
                            while True:
                                data = remote_end.recv(1024)
                                if not data:
                                    return
                                remote_end.sendall(b"tcp:" + data)
                        except OSError:
                            return

                threading.Thread(target=echo, daemon=True).start()
                return channel

        server = LocalSocksServer(FakeTransport(), "127.0.0.1", 0)
        port = server.listener.getsockname()[1]
        server.start()
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            client.settimeout(2)
            client.sendall(b"\x05\x01\x00")
            self.assertEqual(client.recv(2), b"\x05\x00")
            host = b"internet.test"
            client.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (80).to_bytes(2, "big"))
            self.assertEqual(client.recv(10), b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            client.sendall(b"GET /")
            self.assertEqual(client.recv(9), b"tcp:GET /")
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
