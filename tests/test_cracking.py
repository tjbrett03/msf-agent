"""
Hash cracking tests. No real john binary required: subprocess.run in
tools.cracking is mocked so the crack run and the --show read return canned
output. Isolated temp DB via DB_PATH set before importing memory.
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tools.cracking as cracking
import tools.memory as memory


def _completed(stdout="", returncode=0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    return proc


class TestCrackHashes(unittest.TestCase):

    def test_cracks_one_user_and_writes_password(self):
        host = "10.77.0.1"
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "msfadmin",
            "password": None, "hash": "$1$abc$realhash", "source": "shadow",
        })
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "user2",
            "password": None, "hash": "$1$def$otherhash", "source": "shadow",
        })

        # First call = crack run (no useful stdout), second = --show.
        show_out = "msfadmin:msfadmin:1000:1000:...\n\n1 password hash cracked, 1 left\n"
        with patch("tools.cracking.subprocess.run") as run:
            run.side_effect = [_completed(), _completed(stdout=show_out)]
            result = cracking.crack_hashes(host)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["cracked"], [{"username": "msfadmin", "password": "msfadmin"}])

        rows = memory.query("credential", {"host_ip": host})["rows"]
        cracked = next(r for r in rows if r["username"] == "msfadmin")
        self.assertEqual(cracked["password"], "msfadmin")

    def test_uncracked_user_stays_none(self):
        host = "10.77.0.2"
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "alice",
            "password": None, "hash": "$1$aaa$alicehash", "source": "shadow",
        })
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "bob",
            "password": None, "hash": "$1$bbb$bobhash", "source": "shadow",
        })

        # Only alice cracks.
        show_out = "alice:secret:...\n\n1 password hash cracked, 1 left\n"
        with patch("tools.cracking.subprocess.run") as run:
            run.side_effect = [_completed(), _completed(stdout=show_out)]
            result = cracking.crack_hashes(host)

        self.assertEqual(result["cracked"], [{"username": "alice", "password": "secret"}])
        rows = memory.query("credential", {"host_ip": host})["rows"]
        bob = next(r for r in rows if r["username"] == "bob")
        self.assertIsNone(bob["password"])

    def test_no_uncracked_hashes(self):
        host = "10.77.0.3"
        # Already has a password, so not a candidate.
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "done",
            "password": "alreadyknown", "hash": "$1$ccc$donehash", "source": "shadow",
        })
        with patch("tools.cracking.subprocess.run") as run:
            result = cracking.crack_hashes(host)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["cracked"], [])
        run.assert_not_called()

    def test_john_missing_returns_structured_error(self):
        host = "10.77.0.4"
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "carol",
            "password": None, "hash": "$1$ddd$carolhash", "source": "shadow",
        })
        with patch("tools.cracking.subprocess.run", side_effect=FileNotFoundError()):
            result = cracking.crack_hashes(host)

        self.assertEqual(result["status"], "error")
        self.assertIn("john", result["error"].lower())

    def test_summary_line_is_not_treated_as_credential(self):
        host = "10.77.0.5"
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "dave",
            "password": None, "hash": "$1$eee$davehash", "source": "shadow",
        })
        # --show output where the only colon-bearing line is the real crack;
        # the summary line has no second colon field and must be ignored.
        show_out = "dave:hunter2:1001:1001:...\n\n1 password hash cracked\n"
        with patch("tools.cracking.subprocess.run") as run:
            run.side_effect = [_completed(), _completed(stdout=show_out)]
            result = cracking.crack_hashes(host)

        self.assertEqual(result["cracked"], [{"username": "dave", "password": "hunter2"}])


class TestSetCredentialPassword(unittest.TestCase):

    def test_updates_matching_row_by_hash(self):
        host = "10.77.1.1"
        memory.write("credential", {
            "host_ip": host, "service": "shadow", "username": "eve",
            "password": None, "hash": "$1$fff$evehash", "source": "shadow",
        })
        result = memory.set_credential_password(host, "$1$fff$evehash", "p4ss")
        self.assertEqual(result["status"], "ok")

        rows = memory.query("credential", {"host_ip": host})["rows"]
        eve = next(r for r in rows if r["username"] == "eve")
        self.assertEqual(eve["password"], "p4ss")

    def test_no_match_is_still_ok(self):
        result = memory.set_credential_password("10.77.1.2", "$1$nope$nohash", "x")
        self.assertEqual(result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
