"""Regression tests for npm integrity values in the web CycloneDX SBOM."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate_sbom


class WebIntegrityTests(unittest.TestCase):
    def components(self, integrity):
        with tempfile.TemporaryDirectory() as directory:
            web = Path(directory) / "web"
            web.mkdir()
            package = {"version": "1.0.0", "dev": True}
            if integrity is not None:
                package["integrity"] = integrity
            (web / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/example": package},
            }), encoding="utf-8")
            with patch.object(generate_sbom, "ROOT", directory):
                return generate_sbom.web_components()

    def test_sri_digests_are_decoded_to_cyclonedx_hex(self):
        # Known digests of "abc", independently checked against standard vectors.
        cases = (
            ("sha1-qZk+NkcGgWq6PiVxeFDCbJzQ2J0=", "SHA-1",
             "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=", "SHA-256",
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn", "SHA-384",
             "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            ("sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==", "SHA-512",
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        )
        for integrity, algorithm, digest in cases:
            with self.subTest(algorithm=algorithm):
                self.assertEqual(self.components(integrity)[0]["hashes"],
                                 [{"alg": algorithm, "content": digest}])

    def test_multiple_sri_hashes_are_preserved(self):
        component = self.components(
            "sha1-qZk+NkcGgWq6PiVxeFDCbJzQ2J0= "
            "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")[0]
        self.assertEqual(component["hashes"], [
            {"alg": "SHA-1", "content": "a9993e364706816aba3e25717850c26c9cd0d89d"},
            {"alg": "SHA-256", "content": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        ])

    def test_invalid_integrity_is_rejected_instead_of_emitting_invalid_hashes(self):
        for integrity in ("sha512-not!base64", "sha512-YWJj", "sha512-",
                          "sha999-YWJj", "sha512", "   "):
            with self.subTest(integrity=integrity):
                with self.assertRaises(ValueError):
                    self.components(integrity)

    def test_dependency_without_integrity_has_no_hashes(self):
        self.assertNotIn("hashes", self.components(None)[0])


if __name__ == "__main__":
    unittest.main()
