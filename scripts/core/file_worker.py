"""Unprivileged worker used only for the isolated Linux DAC experiment.

Every command opens and closes a fresh descriptor. The protected directory is
root-owned and non-writable by the worker. No file modes or policy are changed
here. All names and operations are allowlisted.
"""
import errno
import json
import os
import sys
import time


def main():
    root = sys.argv[1]
    print(json.dumps({"ready": True, "uid": os.getuid(), "gid": os.getgid()}), flush=True)
    names = {"sensitive.txt", "diagnostic.txt", "business.txt", "sink.txt"}
    for line in sys.stdin:
        command = json.loads(line)
        op, name = command.get("op"), command.get("name")
        if op == "stop":
            return
        start = time.monotonic_ns()
        result = {"op": op, "name": name, "start_ns": start,
                  "ok": False, "errno": None, "bytes": 0}
        try:
            if name not in names or op not in ("read", "append"):
                raise OSError(errno.EINVAL, "unsupported operation")
            if op == "read":
                with open(os.path.join(root, name), "rb") as stream:
                    data = stream.read()
                result.update(ok=True, bytes=len(data))
            else:
                payload = command["payload"].encode("utf-8")
                with open(os.path.join(root, name), "ab", buffering=0) as stream:
                    written = stream.write(payload)
                result.update(ok=written == len(payload), bytes=written)
        except OSError as exc:
            result["errno"] = exc.errno
        result["end_ns"] = time.monotonic_ns()
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
