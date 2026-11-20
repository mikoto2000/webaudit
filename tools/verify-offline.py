"""Linux amd64: run real GeoIP CLI paths with kernel-enforced network denial.
No dependencies. Any socket/connect/send syscall kills the child process rather
than returning an error that the application could silently ignore.
"""
import ctypes
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

assert platform.system() == "Linux" and platform.machine() == "x86_64"
class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

def deny_network():
    libc = ctypes.CDLL(None, use_errno=True)
    # Guard syscall ABI, then deny socket/connect/accept/send/recv/listen/bind/
    # socketpair, newer accept4 and message batching, and io_uring bypasses.
    rules = [Filter(0x20, 0, 0, 4), Filter(0x15, 1, 0, 0xc000003e),
             Filter(0x06, 0, 0, 0x80000000), Filter(0x20, 0, 0, 0)]
    for number in list(range(41, 56)) + [288, 299, 307, 425, 426, 427]:
        rules += [Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x80000000)]
    rules += [Filter(0x06, 0, 0, 0x7fff0000)]
    filters = (Filter * len(rules))(*rules)
    program = Program(len(rules), filters)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        os._exit(125)

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    exe = Path(tmp) / "webaudit"
    subprocess.run(["go", "build", "-o", str(exe), "./cmd/webaudit"], cwd=root, check=True)
    # Verify the guard actually kills attempted networking before testing WebAudit.
    import sys
    probe = subprocess.run([sys.executable, "-c", "import socket; socket.socket()"], preexec_fn=deny_network)
    assert probe.returncode < 0, probe.returncode
    log = Path(tmp) / "access.log"
    log.write_text("".join(f'{ip} - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0\n'
                           for ip in ["8.8.8.8", "8.8.8.8", "2606:4700::1111", "1.1.1.1", "10.0.0.1", "::1"]))
    fixture = root / "audit/testdata/geoip"
    explicit = ["--geoip-country", str(fixture / "country.mmdb"), "--geoip-asn", str(fixture / "asn.mmdb")]
    for extra in [[], explicit]:
        for fmt in ["json", "csv", "html"]:
            run = subprocess.run([str(exe), str(log), "--format", fmt] + extra,
                                 preexec_fn=deny_network, capture_output=True, text=True, check=True)
            if fmt == "json":
                report = json.loads(run.stdout)
                assert ("geoip" in report) == bool(extra)
    geo = exe.parent / "geoip"
    geo.mkdir()
    import shutil
    for role in ["country", "asn"]:
        shutil.copyfile(fixture / (role + ".mmdb"), geo / (role + ".mmdb"))
    run = subprocess.run([str(exe), str(log), "--format", "json"], cwd="/",
                         preexec_fn=deny_network, capture_output=True, text=True, check=True)
    assert json.loads(run.stdout)["geoip"]["databases"]
print("PASS: seccomp guard self-test; disabled, explicit and executable-relative auto GeoIP; JSON/CSV/HTML; no network syscalls")
