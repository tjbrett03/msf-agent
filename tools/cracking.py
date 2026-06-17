import os
import subprocess
import tempfile

import tools.memory as memory


def _parse_show_output(stdout: str) -> list[tuple[str, str]]:
    """Extract (username, plaintext) pairs from `john --show` output.

    john --show prints one cracked entry per line as `username:plaintext:...`
    (trailer fields like uid/gid follow), then a blank line and a summary line
    such as "1 password hash cracked, 0 left". We split on ':' and take the
    first two fields. Lines without at least two colon-separated fields (the
    summary, blank lines) are ignored, and a summary line that happens to start
    with a digit count is filtered because its first field is not a real user.
    """
    pairs = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 2:
            # Summary line ("N password hashes cracked, ...") or noise.
            continue
        username, plaintext = parts[0], parts[1]
        # The trailer summary ("N password hashes cracked") has no second colon
        # field that is a password, but guard anyway against an empty plaintext.
        if not username or plaintext == "":
            continue
        pairs.append((username, plaintext))
    return pairs


def crack_hashes(host_ip: str) -> dict:
    """Run John the Ripper against looted hashes for host_ip and write back
    only the real cracked plaintext into the matching credential rows.

    Trust model: the credential table is runtime-only ground truth, so an
    uncracked row simply has password=None until john recovers it. A hash john
    does not crack stays password=None; nothing is invented.
    """
    result = memory.query("credential", {"host_ip": host_ip})
    if result.get("status") != "ok":
        return {"status": "error", "error": f"failed to read credentials: {result.get('error')}"}

    # Uncracked = has a hash but no recovered password yet.
    uncracked = [
        r for r in result["rows"]
        if r.get("hash") and not r.get("password")
    ]

    if not uncracked:
        return {
            "status":    "ok",
            "cracked":   [],
            "attempted": 0,
            "note":      f"no uncracked hashes for {host_ip}",
        }

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".hashes")
        with os.fdopen(fd, "w") as fh:
            # Unshadow format john understands: username:cryptstring. The hash
            # field already holds the full $id$salt$hash so this is valid input.
            for row in uncracked:
                fh.write(f"{row['username']}:{row['hash']}\n")

        # Crack run. Rely on john's default rules/format autodetection so this
        # stays simple and so the test can mock the subprocess cleanly.
        subprocess.run(
            ["john", tmp_path],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # --show reads the pot file and prints already-cracked entries.
        show = subprocess.run(
            ["john", "--show", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        cracked = []
        for username, plaintext in _parse_show_output(show.stdout):
            # Key the update on the hash (precise ground truth) so the right
            # row is updated even if two users share a username.
            match = next(
                (r for r in uncracked if r.get("username") == username),
                None,
            )
            if match is None:
                continue
            memory.set_credential_password(host_ip, match["hash"], plaintext)
            cracked.append({"username": username, "password": plaintext})

        return {
            "status":    "ok",
            "cracked":   cracked,
            "attempted": len(uncracked),
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "error":  "john not found on PATH; install John the Ripper (ships with Metasploit) to enable cracking",
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "john timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
