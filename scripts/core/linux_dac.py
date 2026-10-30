"""Real Linux file-permission executor, intentionally NOT an eBPF backend.

Controller must be root; worker drops to uid/gid 65534. Only fresh-open file
read/append operations inside a private /tmp sandbox are covered. Open-FD
revocation, networking, exec, containers, observation integrity and hostile
kernel/controller are outside this backend's guarantees.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time


class LinuxDACExecutor:
    filenames = ("sensitive.txt", "diagnostic.txt", "business.txt", "sink.txt")

    def __init__(self):
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("linux-dac requires Linux root to create a separate-UID worker")
        self._temp = tempfile.TemporaryDirectory(prefix="ertb-dac-", dir="/tmp")
        self.root = Path(self._temp.name)
        self.root.chmod(0o755)
        for name in self.filenames:
            path = self.root / name
            path.write_bytes(b"fixture\n" if name in ("sensitive.txt", "diagnostic.txt") else b"")
            path.chmod(0o666)
        # Copy only the small worker into the sandbox; no dependence on repo mount permissions.
        worker = self.root / "worker.py"
        worker.write_bytes(Path(__file__).with_name("file_worker.py").read_bytes())
        worker.chmod(0o444)

        def drop_privileges():
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)

        self.process = subprocess.Popen(
            [sys.executable, "-I", "-B", str(worker), str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, cwd=str(self.root), preexec_fn=drop_privileges,
        )
        ready = self._read()
        if not ready.get("ready") or ready.get("uid") != 65534:
            self.close()
            raise RuntimeError("worker privilege separation failed")
        self.permissions = "read-write"

    def _read(self):
        if not select.select([self.process.stdout], [], [], 5)[0]:
            raise RuntimeError("worker response timeout")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("worker exited: " + self.process.stderr.read())
        return json.loads(line)

    def apply(self, permissions):
        modes = {"read-write": 0o666, "read-only": 0o444, "deny-all": 0o000}
        mode = modes[permissions]
        started = time.monotonic_ns()
        for name in self.filenames:
            (self.root / name).chmod(mode)
        self.permissions = permissions
        return {"start_ns": started, "end_ns": time.monotonic_ns(),
                "permissions": permissions}

    def operation(self, op, name, payload=""):
        # Always dispatch, even when the policy says deny. Kernel result is the evidence.
        command = {"op": op, "name": name, "payload": payload}
        self.process.stdin.write(json.dumps(command) + "\n")
        self.process.stdin.flush()
        return self._read()

    def size(self, name):
        if name not in self.filenames:
            raise ValueError("unknown file")
        return (self.root / name).stat().st_size

    def close(self):
        if getattr(self, "process", None):
            if self.process.poll() is None:
                try:
                    self.process.stdin.write('{"op":"stop"}\n')
                    self.process.stdin.flush()
                    self.process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=2)
            for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                pipe.close()
        self._temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
