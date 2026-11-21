"""Linux amd64: run real GeoIP CLI paths with kernel-enforced network denial.
No dependencies. Any socket/connect/send syscall kills the child process rather
than returning an error that the application could silently ignore.
"""
import ctypes
import json
import hashlib
import resource
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
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
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
    env = dict(os.environ, XDG_DATA_HOME=str(Path(tmp) / "data"))
    exe = Path(tmp) / "webaudit"
    subprocess.run(["go", "build", "-o", str(exe), "./cmd/webaudit"], cwd=root, check=True)
    # Verify the guard actually kills attempted networking before testing WebAudit.
    import sys
    probe = subprocess.run([sys.executable, "-c", "import socket; socket.socket()"], preexec_fn=deny_network)
    assert probe.returncode < 0, probe.returncode
    log = Path(tmp) / "access.log"
    log.write_text("".join(f'{ip} - - [01/Nov/2026:00:00:00 +0000] "GET /.env HTTP/1.1" 404 0\n'
                           for ip in ["8.8.8.8", "8.8.8.8", "2606:4700::1111", "1.1.1.1", "10.0.0.1", "::1"]))
    missing = subprocess.run([str(exe), "geoip", "status"], env=env, preexec_fn=deny_network,
                             capture_output=True, text=True, check=True)
    assert "Not installed" in missing.stdout
    fixture = root / "audit/testdata/geoip"
    explicit = ["--geoip-country", str(fixture / "country.mmdb"), "--geoip-asn", str(fixture / "asn.mmdb")]
    for extra in [[], explicit]:
        # Real watch startup, parsing, detection, JSONL and SIGINT under seccomp.
        import signal
        child = subprocess.Popen([str(exe), "watch", str(log), "--from", "beginning",
                                  "--no-state", "--format", "jsonl"] + extra,
                                 env=env, preexec_fn=deny_network, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            import selectors
            ready = selectors.DefaultSelector()
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(10), "watch emitted no event"
            event = json.loads(child.stdout.readline())
            assert event["event_type"] == "incident_created" and event["schema_version"] == 1
            assert ("geoip" in event) == bool(extra)
            child.send_signal(signal.SIGINT)
            _, diagnostics = child.communicate(timeout=10)
            assert child.returncode == 0, diagnostics
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
        for fmt in ["json", "csv", "html"]:
            run = subprocess.run([str(exe), str(log), "--format", fmt] + extra,
                                 env=env, preexec_fn=deny_network, capture_output=True, text=True, check=True)
            if fmt == "json":
                report = json.loads(run.stdout)
                assert ("geoip" in report) == bool(extra)
    geo = exe.parent / "geoip"
    geo.mkdir()
    import shutil
    for role in ["country", "asn"]:
        shutil.copyfile(fixture / (role + ".mmdb"), geo / (role + ".mmdb"))
    run = subprocess.run([str(exe), str(log), "--format", "json"], cwd="/",
                         env=env, preexec_fn=deny_network, capture_output=True, text=True, check=True)
    assert json.loads(run.stdout)["geoip"]["databases"]
    # Install a synthetic managed generation. These are test-supplied publication
    # metadata, not inferred release metadata for arbitrary user files.
    managed = Path(env["XDG_DATA_HOME"]) / "webaudit/geoip"
    generation = managed / "versions/gen-offline"
    generation.mkdir(parents=True)
    databases = []
    for role in ["country", "asn"]:
        data = (fixture / (role + ".mmdb")).read_bytes()
        (generation / (role + ".mmdb")).write_bytes(data)
        databases.append(dict(role=role, provider="DB-IP Lite", type="DBIP-" + ("Country" if role == "country" else "ASN") + "-Lite",
                              version="2026-11", url="https://download.db-ip.com/free/dbip-" + role + "-lite-2026-11.mmdb.gz",
                              downloaded_at="2026-11-20T00:00:00Z", build_time="2026-11-01T00:00:00Z", size=len(data),
                              sha256=hashlib.sha256(data).hexdigest(), source_sha1=hashlib.sha1(data).hexdigest(),
                              file="versions/gen-offline/" + role + ".mmdb"))
    (managed / "metadata.json").write_text(json.dumps(dict(format=1, current=dict(id="gen-offline", databases=databases),
                                                        last_checked_at="2026-11-20T00:00:00Z")))
    for operation in ["status", "download"]:  # Existing download must avoid HTTP, too.
        run = subprocess.run([str(exe), "geoip", operation], env=env, preexec_fn=deny_network,
                             capture_output=True, text=True, check=True)
        assert "2026-11" in run.stdout
    for fmt in ["json", "csv", "html"]:
        run = subprocess.run([str(exe), str(log), "--format", fmt], env=env, preexec_fn=deny_network,
                             capture_output=True, text=True, check=True)
        assert "2026-11" in run.stdout
        if fmt == "json":
            report = json.loads(run.stdout)
            assert report["geoip"]["enabled"] and report["geoip"]["databases"][0]["generation"] == "gen-offline"
    (generation / "country.mmdb").write_bytes(b"corrupt")
    run = subprocess.run([str(exe), "geoip", "status"], env=env, preexec_fn=deny_network,
                         capture_output=True, text=True)
    assert run.returncode == 1 and "FAILED" in run.stderr
    run = subprocess.run([str(exe), str(log), "--format", "json"], env=env, preexec_fn=deny_network,
                         capture_output=True, text=True, check=True)
    assert "geoip" not in json.loads(run.stdout) and "Managed GeoIP unavailable" in run.stderr
print("PASS: seccomp guard; offline watch JSONL/SIGINT with and without GeoIP; disabled/explicit/legacy/managed analysis; status; existing download; corrupt DB fallback; JSON/CSV/HTML; no network syscalls")
