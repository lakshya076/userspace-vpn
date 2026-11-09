import os
import struct
import unittest

from uvpn import fec, obfs, stun
from uvpn import protocol as p

from .test_protocol import handshake


def sessions(mode: str):
    client, server, _ = handshake()
    client.fec = fec.Encoder(mode)
    return client, server


class FecTest(unittest.TestCase):
    def test_recovers_any_single_loss(self):
        payloads = [os.urandom(n) for n in (40, 1400, 7, 300)]
        for lost in range(4):
            client, server = sessions("4")
            wire = [client.seal(p.DATA, x) for x in payloads]
            [parity] = client.flush_parity(0)
            for i, packet in enumerate(wire):
                if i != lost:
                    server.open(packet)
            rebuilt = server.recover(parity)
            self.assertEqual(server.open(rebuilt, recovered=True), (p.DATA, payloads[lost]))

    def test_two_losses_not_recoverable(self):
        client, server = sessions("3")
        wire = [client.seal(p.DATA, b"x" * 50) for _ in range(3)]
        [parity] = client.flush_parity(0)
        server.open(wire[0])
        self.assertIsNone(server.recover(parity))

    def test_nothing_lost_nothing_rebuilt(self):
        client, server = sessions("2")
        for packet in [client.seal(p.DATA, b"a" * 30), client.seal(p.DATA, b"b" * 30)]:
            server.open(packet)
        self.assertIsNone(server.recover(client.flush_parity(0)[0]))

    def test_forged_parity_cannot_inject(self):
        client, server = sessions("2")
        good = client.seal(p.DATA, b"a" * 30)
        client.seal(p.DATA, b"b" * 30)  # lost
        parity = bytearray(client.flush_parity(0)[0])
        parity[-1] ^= 0xFF
        server.open(good)
        with self.assertRaises(p.AuthError):
            server.open(server.recover(bytes(parity)), recovered=True)

    def test_partial_block_flushes_after_delay(self):
        client, _ = sessions("8")
        client.seal(p.DATA, b"x" * 30)
        self.assertEqual(client.flush_parity(client.fec.started), [])
        self.assertEqual(len(client.flush_parity(client.fec.started + 2 * fec.FLUSH_DELAY)), 1)

    def test_adaptive_block_size(self):
        enc = fec.Encoder("adaptive")
        self.assertEqual(enc.k, 0)
        for loss, k in ((0.0, 0), (0.01, 8), (0.07, 4), (0.3, 1)):
            enc.adapt(loss)
            self.assertEqual(enc.k, k)

    def test_loss_measurement(self):
        client, server = sessions("off")
        for i in range(100):
            packet = client.seal(p.DATA, b"x" * 20)
            if i % 10 != 0:
                server.open(packet)
        self.assertEqual(server.measure_loss(), 100)  # 10 of 100 lost
        self.assertEqual(server.measure_loss(), p.LOSS_UNKNOWN)


class ObfuscationTest(unittest.TestCase):
    def test_round_trip_and_no_fixed_bytes(self):
        o = obfs.Obfuscator(os.urandom(32))
        client, server, _ = handshake()
        wire = [client.seal(p.DATA, b"same payload") for _ in range(50)]
        masked = [o.apply(w) for w in wire]
        for w, m in zip(wire, masked):
            self.assertEqual(o.apply(m), w)
        # The cleartext header starts with version 1 and type DATA; masked ones vary.
        self.assertTrue(all(w[:2] == b"\x01\x03" for w in wire))
        self.assertGreater(len({m[:2] for m in masked}), 40)

    def test_wrong_key_garbles_header(self):
        wire = handshake()[0].seal(p.DATA, b"x")
        masked = obfs.Obfuscator(os.urandom(32)).apply(wire)
        self.assertNotEqual(obfs.Obfuscator(os.urandom(32)).apply(masked)[:16], wire[:16])

    def test_padding_buckets(self):
        packet = bytes(20) + b"payload"
        self.assertEqual(len(obfs.pad_ip_packet(packet, 1400)), 128)
        self.assertEqual(len(obfs.pad_ip_packet(bytes(1390), 1400)), 1400)

    def test_padded_handshake_still_parses(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        psk = os.urandom(32)
        packet, init = p.build_init(psk, os.urandom(16), X25519PrivateKey.generate(), padding=37)
        self.assertEqual(len(packet), p.INIT_LEN + 37)
        self.assertEqual(p.parse_init(psk, packet).mac, init.mac)


class StunTest(unittest.TestCase):
    def test_parse_xor_mapped_address(self):
        request, txid = stun.build_request()
        self.assertEqual(len(request), 20)
        port, ip = 51820, 0xCB007107  # 203.0.113.7
        value = struct.pack("!BBHI", 0, 1, port ^ (stun.MAGIC >> 16), ip ^ stun.MAGIC)
        attr = struct.pack("!HH", stun.ATTR_XOR_MAPPED, len(value)) + value
        response = struct.pack("!HHI", stun.BINDING_SUCCESS, len(attr), stun.MAGIC) + txid + attr
        self.assertEqual(stun.parse_response(response, txid), ("203.0.113.7", 51820))

    def test_rejects_wrong_transaction(self):
        _, txid = stun.build_request()
        response = struct.pack("!HHI", stun.BINDING_SUCCESS, 0, stun.MAGIC) + os.urandom(12)
        with self.assertRaises(ValueError):
            stun.parse_response(response, txid)


if __name__ == "__main__":
    unittest.main()
