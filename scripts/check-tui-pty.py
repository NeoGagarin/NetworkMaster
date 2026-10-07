"""Linux PTY smoke test: real event loop, keys, resize and terminal restoration."""

import fcntl
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


def drain(master, seconds=0.4):
    data = bytearray()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            chunk = os.read(master, 65536)
            data.extend(chunk)
            # Emulate the cursor-position response a real xterm supplies.
            if b"\x1b[6n" in chunk:
                os.write(master, b"\x1b[1;1R")
    return bytes(data)


def default_binary():
    # Ask Cargo, since the target directory can be moved by config or CARGO_TARGET_DIR.
    metadata = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    return Path(json.loads(metadata)["target_directory"]) / "debug" / "netmaster"


binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else default_binary()
for key, expected in [(b"q", 0), (b"\x03", 130)]:
    master, slave = pty.openpty()
    before = termios.tcgetattr(slave)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    with tempfile.TemporaryDirectory(prefix="networkmaster-pty-") as directory:
        env = dict(os.environ, TERM="xterm-256color", NETMASTER_NET="deny")
        process = subprocess.Popen(
            [binary, "--data-dir", directory, "--ascii", "--no-color"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            start_new_session=True,
            # Single-threaded script; TIOCSCTTY must run in the child before exec.
            preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0),  # noqa: PLW1509
        )
        try:
            output = b""
            deadline = time.monotonic() + 5
            while b"Dashboard" not in output and time.monotonic() < deadline:
                output += drain(master, 0.25)
            assert b"Dashboard" in output, output.decode(errors="replace")
            assert not termios.tcgetattr(slave)[3] & termios.ICANON, "raw mode was not enabled"
            os.write(master, b"0")
            output += drain(master)
            os.write(master, b"?")
            output += drain(master)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
            os.kill(process.pid, signal.SIGWINCH)
            resized = drain(master)
            assert resized, "resize did not redraw"
            output += resized
            os.write(master, key)
            assert process.wait(timeout=5) == expected
            output += drain(master)
            assert termios.tcgetattr(slave) == before, "terminal mode was not restored"
            assert b"\x1b[?1049l" in output and b"\x1b[?25h" in output, "screen/cursor not restored"
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    os.close(master)
    os.close(slave)
print("TUI PTY: launch, navigation, resize, quit/Ctrl+C and terminal restoration passed.")
