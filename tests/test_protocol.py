import os
import time
import unittest
from ipaddress import IPv4Address

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from uvpn import protocol as p

PSK = os.urandom(32)


def handshake():
    """Run INIT/RESP in memory; return (client session, server session)."""
    cpriv, spriv = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    packet, init = p.build_init(PSK, os.urandom(16), cpriv)
    got = p.parse_init(PSK, packet)
    c2s, s2c = p.derive_keys(PSK, spriv, got.client_public, got.client_public, p.public_bytes(spriv))
    resp_pkt = p.build_resp(PSK, 0x1234, spriv, IPv4Address("10.8.0.2"), 24, 1400, got.mac)
    resp = p.parse_resp(PSK, resp_pkt, init.mac)
    cc2s, cs2c = p.derive_keys(PSK, cpriv, resp.server_public, init.client_public, resp.server_public)
    assert (cc2s, cs2c) == (c2s, s2c)
    return p.Session(resp.session_id, cc2s, cs2c), p.Session(0x1234, s2c, c2s), resp


class HandshakeTest(unittest.TestCase):
    def test_round_trip(self):
        client, server, resp = handshake()
        self.assertEqual(resp.tunnel_ip, IPv4Address("10.8.0.2"))
        self.assertEqual((resp.prefix_len, resp.mtu), (24, 1400))
        self.assertEqual(server.open(client.seal(p.DATA, b"ping")), (p.DATA, b"ping"))
        self.assertEqual(client.open(server.seal(p.DATA, b"pong")), (p.DATA, b"pong"))

    def test_wrong_psk_rejected(self):
        packet, _ = p.build_init(os.urandom(32), os.urandom(16), X25519PrivateKey.generate())
        with self.assertRaises(p.AuthError):
            p.parse_init(PSK, packet)

    def test_stale_init_rejected(self):
        old = time.time_ns() - int(10 * 60 * 1e9)
        packet, _ = p.build_init(PSK, os.urandom(16), X25519PrivateKey.generate(), now_ns=old)
        with self.assertRaises(p.ProtocolError):
            p.parse_init(PSK, packet)

    def test_resp_bound_to_its_init(self):
        _, init_a = p.build_init(PSK, os.urandom(16), X25519PrivateKey.generate())
        _, init_b = p.build_init(PSK, os.urandom(16), X25519PrivateKey.generate())
        resp = p.build_resp(PSK, 1, X25519PrivateKey.generate(), IPv4Address("10.8.0.2"), 24, 1400, init_a.mac)
        with self.assertRaises(p.AuthError):
            p.parse_resp(PSK, resp, init_b.mac)


class DataPathTest(unittest.TestCase):
    def test_every_tampered_byte_rejected(self):
        client, server, _ = handshake()
        packet = client.seal(p.DATA, b"secret payload")
        for i in range(len(packet)):
            bad = bytearray(packet)
            bad[i] ^= 0x01
            with self.assertRaises(p.ProtocolError, msg=f"byte {i}"):
                server.open(bytes(bad))
        self.assertEqual(server.open(packet)[1], b"secret payload")  # window untouched by forgeries

    def test_replay_rejected(self):
        client, server, _ = handshake()
        packet = client.seal(p.DATA, b"x")
        server.open(packet)
        with self.assertRaises(p.ReplayError):
            server.open(packet)

    def test_plaintext_not_on_wire(self):
        client, _, _ = handshake()
        self.assertNotIn(b"secret payload", client.seal(p.DATA, b"secret payload"))


class ReplayWindowTest(unittest.TestCase):
    def test_out_of_order_inside_window(self):
        w = p.ReplayWindow(64)
        for seq in (5, 3, 4, 10):
            self.assertTrue(w.check(seq))
            w.update(seq)
        self.assertFalse(w.check(3))
        self.assertTrue(w.check(7))

    def test_too_old(self):
        w = p.ReplayWindow(64)
        w.update(1000)
        self.assertFalse(w.check(1000 - 64))
        self.assertTrue(w.check(1000 - 63))

    def test_large_jump(self):
        w = p.ReplayWindow(64)
        w.update(1)
        w.update(10**12)
        self.assertFalse(w.check(10**12))
        self.assertTrue(w.check(10**12 - 1))


if __name__ == "__main__":
    unittest.main()
