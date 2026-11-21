# flake8: noqa: F403,F405
from common import *  # isort:skip

if utils.USE_BLS:
    import trezorbls

    # Seed of EIP-2333 test case 1 (https://eips.ethereum.org/EIPS/eip-2333).
    SEED = bytes.fromhex(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    )
    ROOT = bytes(range(32))


@unittest.skipUnless(utils.USE_BLS, "BLS support not enabled")
class TestEth2Bls(unittest.TestCase):
    def test_public_key(self):
        pubkey = trezorbls.public_key(SEED, 0)
        self.assertEqual(len(pubkey), 48)

        # a different validator index derives a different key
        other_pubkey = trezorbls.public_key(SEED, 1)
        self.assertEqual(len(other_pubkey), 48)
        self.assertNotEqual(pubkey, other_pubkey)

    def test_sign(self):
        signature = trezorbls.sign(SEED, 0, ROOT)
        self.assertEqual(len(signature), 96)

        # deterministic for the same inputs
        self.assertEqual(signature, trezorbls.sign(SEED, 0, ROOT))
        # differs per validator index and per signing root
        self.assertNotEqual(signature, trezorbls.sign(SEED, 1, ROOT))
        self.assertNotEqual(signature, trezorbls.sign(SEED, 0, b"\x00" * 32))

    def test_invalid_seed_length(self):
        for bad_seed in (b"", b"\x00" * 15, b"\x00" * 65):
            with self.assertRaises(ValueError):
                trezorbls.public_key(bad_seed, 0)
            with self.assertRaises(ValueError):
                trezorbls.sign(bad_seed, 0, ROOT)

    def test_invalid_signing_root_length(self):
        for bad_root in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                trezorbls.sign(SEED, 0, bad_root)


if __name__ == "__main__":
    unittest.main()
