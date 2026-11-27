# SPDX-License-Identifier: AGPL-3.0-or-later
"""A real process with its stdout and stderr in a given state, on Linux, macOS and Windows, each state made with the
system's own means and no shell (27/11/2026: the receipt tests ran under bash with /dev/full and /proc, so on macOS and
Windows they were all skipped):

- a file (optionally with bytes already in it, appended to), a pipe read at once, after 0.5 s, or left after 100 bytes;
- a pipe whose reader has gone before the start (EPIPE; Windows: ERROR_NO_DATA);
- closed: POSIX closes the descriptor in the child; Windows starts the child with no standard handle (STARTUPINFO);
- read-only: the descriptor is a file opened for reading (EBADF; Windows: ERROR_ACCESS_DENIED);
- /dev/full (ENOSPC on every write): Linux only — macOS and Windows have no such device (NO_DEVFULL);
- a file size limit (RLIMIT_FSIZE): POSIX only — Windows has no per-process file size limit (NO_FSIZE).
"""
import os
import subprocess
import tempfile
import time

WIN = os.name == "nt"
try:
    import resource
except ImportError:   # Windows
    resource = None

HAVE_DEVFULL = os.path.exists("/dev/full")
HAVE_FSIZE = resource is not None
NO_DEVFULL = ("no device whose every write fails with ENOSPC on this system (/dev/full is Linux): the lost write is "
              "measured here with the pipe whose reader has gone and with the closed descriptor")
NO_FSIZE = "Windows has no per-process file size limit (RLIMIT_FSIZE): the short write it causes has no equivalent there"
LOSING = ("pipe_closed", "closed", "readonly") + (("devfull",) if HAVE_DEVFULL else ())


def _handle(f):
    import msvcrt
    h = msvcrt.get_osfhandle(f if isinstance(f, int) else f.fileno())
    os.set_handle_inheritable(h, True)
    return h


def _target(kind, path, opened):
    """the object a standard stream of the child is pointed at; None = closed"""
    if kind == "file":
        f = open(path, "ab")
    elif kind == "devfull":
        f = open("/dev/full", "wb")
    elif kind == "readonly":
        open(path, "ab").close()
        f = open(path, "rb")
    elif kind == "pipe_closed":
        r, w = os.pipe()
        os.close(r)
        opened.append(w)
        return w
    elif kind == "closed":
        return None
    elif kind == "devnull":
        f = open(os.devnull, "wb")
    else:
        raise ValueError(kind)
    opened.append(f)
    return f


def start(argv, out, err="file", env=None, cwd=None, fsize=None, td=None, pre=b""):
    """Popen of argv with stdout `out` and stderr `err` ("file", "devfull", "pipe_closed", "closed", "readonly",
    "devnull"; stdout also "pipe"). Returns (Popen, stdout path, stderr path, things to close after it ended)."""
    o, e = os.path.join(td, "out"), os.path.join(td, "err")
    with open(o, "wb") as f:
        f.write(pre)
    open(e, "wb").close()
    opened = []
    so = subprocess.PIPE if out == "pipe" else _target(out, o, opened)
    se = _target(err, e, opened)
    pre_fn = None
    if fsize is not None:
        if not HAVE_FSIZE:
            raise RuntimeError(NO_FSIZE)
        pre_fn = lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))  # noqa: E731
    closed = [fd for fd, t, kind in ((1, so, out), (2, se, err)) if kind == "closed"]
    if closed and not WIN:
        lim = pre_fn

        def pre_fn():
            if lim:
                lim()
            for fd in closed:
                os.close(fd)
    if closed and WIN:   # no handle at all for the closed stream: Python in the child sees sys.stdout / sys.stderr None
        if so is subprocess.PIPE:
            raise ValueError("a closed stream with a pipe is not built here")
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESTDHANDLES
        null_in = open(os.devnull, "rb")
        opened.append(null_in)
        si.hStdInput = _handle(null_in)
        si.hStdOutput = 0 if so is None else _handle(so)
        si.hStdError = 0 if se is None else _handle(se)
        si.lpAttributeList = {"handle_list": [h for h in (si.hStdInput, si.hStdOutput, si.hStdError) if h]}
        p = subprocess.Popen(argv, startupinfo=si, close_fds=True, env=env, cwd=cwd)
    else:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=so, stderr=se, env=env, cwd=cwd, preexec_fn=pre_fn)
    return p, o, e, opened


def _close(opened):
    for f in opened:
        f.close() if hasattr(f, "close") else os.close(f)


def run(argv, out="file", err="file", env=None, cwd=None, fsize=None, pre=b"", timeout=120):
    """(exit code, stdout bytes — what follows `pre` in a file, what a pipe carried, None otherwise —, stderr text)"""
    with tempfile.TemporaryDirectory() as td:
        p, o, e, opened = start(argv, {"slow": "pipe", "head100": "pipe"}.get(out, out), err, env, cwd, fsize, td, pre)
        got = None
        try:
            if out == "slow":
                time.sleep(0.5)
                got = p.communicate(timeout=timeout)[0]
            elif out == "head100":
                p.stdout.read(100)
                p.stdout.close()
                p.wait(timeout=timeout)
            elif out == "pipe":
                got = p.communicate(timeout=timeout)[0]
            else:
                p.wait(timeout=timeout)
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            _close(opened)
        if out == "file":
            with open(o, "rb") as f:
                got = f.read()[len(pre):]
        with open(e, "rb") as f:
            err_text = f.read().decode("utf-8", "replace") if err == "file" else ""
        return p.returncode, got, err_text


def cpu_seconds(p):
    """user + system CPU seconds of a live process: /proc (Linux), ps (macOS), GetProcessTimes (Windows)"""
    if WIN:
        import ctypes
        t = [ctypes.c_ulonglong() for _ in range(4)]
        if not ctypes.windll.kernel32.GetProcessTimes(int(p._handle), *(ctypes.byref(x) for x in t)):
            raise OSError("GetProcessTimes failed")
        return (t[2].value + t[3].value) / 1e7   # 100 ns units: kernel + user
    if os.path.exists(f"/proc/{p.pid}/stat"):
        with open(f"/proc/{p.pid}/stat", "rb") as f:
            fields = f.read().rsplit(b")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    r = subprocess.run(["ps", "-o", "time=", "-p", str(p.pid)], capture_output=True, text=True, timeout=10)
    s = r.stdout.strip()
    if r.returncode or not s:
        raise OSError("ps: no such process")
    days, _, s = s.rpartition("-")
    secs = 0.0
    for part in s.split(":"):   # [hh:]mm:ss.cc
        secs = secs * 60 + float(part)
    return secs + (int(days) * 86400 if days else 0)


def set_nonblocking(fd):
    """O_NONBLOCK (POSIX); a Windows pipe takes it through os.set_blocking from Python 3.12 (PIPE_NOWAIT)"""
    os.set_blocking(fd, False)


NONBLOCKING_PIPE = not WIN or __import__("sys").version_info >= (3, 12)
NO_NONBLOCKING_PIPE = "os.set_blocking() takes a Windows pipe from Python 3.12 only: before it the stdlib cannot make one non-blocking"


def deny_writes(test, folder):
    """`folder` refuses new files to this process: mode 0500 (POSIX); on Windows, where the mode does not stop a write,
    an ACL entry that denies writing to Everyone (icacls), removed at cleanup"""
    if WIN:
        subprocess.run(["icacls", folder, "/deny", "*S-1-1-0:(W)"], check=True, capture_output=True, timeout=60)
        test.addCleanup(subprocess.run, ["icacls", folder, "/remove:d", "*S-1-1-0"], capture_output=True, timeout=60)
        return
    os.chmod(folder, 0o500)
    test.addCleanup(os.chmod, folder, 0o700)


def deny_reads(test, path):
    """`path` cannot be read by this process: mode 000 (POSIX); Windows: an ACL entry that denies reading to Everyone"""
    if WIN:
        subprocess.run(["icacls", path, "/deny", "*S-1-1-0:(R)"], check=True, capture_output=True, timeout=60)
        test.addCleanup(subprocess.run, ["icacls", path, "/remove:d", "*S-1-1-0"], capture_output=True, timeout=60)
        return
    os.chmod(path, 0)
    test.addCleanup(os.chmod, path, 0o600)


NO_MEMORY_BOUND = ("macOS: setrlimit(RLIMIT_DATA) raises in the child (measured on the CI's macOS runners, 27/11/2026); "
                   "the child's timeout is the only bound there")


def memory_bound_preexec(limit):
    """POSIX: a preexec_fn that sets RLIMIT_DATA, or None where the kernel refuses it (macOS)"""
    if resource is None or __import__("sys").platform == "darwin":
        return None
    return lambda: resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))


def bound_memory(p, limit):
    """Windows: put the started process `p` in a Job Object whose per-process memory limit is `limit` bytes (the
    equivalent of RLIMIT_DATA). The job handle is kept on `p` so the limit lives as long as the process."""
    import ctypes
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class Extended(ctypes.Structure):
        _fields_ = [("Basic", Basic), ("Io", ctypes.c_ulonglong * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.restype = wintypes.HANDLE
    job = k.CreateJobObjectW(None, None)
    info = Extended()
    info.Basic.LimitFlags = 0x100 | 0x2000   # JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    info.ProcessMemoryLimit = limit
    if not job or not k.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info)) \
            or not k.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(int(p._handle))):
        raise OSError(ctypes.get_last_error(), "Job Object not set")
    p._cra_job = job


DEVICE = "\\\\.\\NUL" if WIN else "/dev/zero"   # a device in place of a document: Windows has no /dev/zero, NUL is its device
NO_FIFO = ("Windows has no FIFO in a folder (its named pipes live under \\\\.\\pipe\\ only): a FIFO at a path the "
           "product chooses itself has no equivalent there")


def fifo(test, folder):
    """the path of a FIFO no one writes to: mkfifo (POSIX); on Windows a named pipe \\\\.\\pipe\\<random> with 64 instances
    waiting for a client (each open takes one), closed at cleanup"""
    if not WIN:
        p = os.path.join(folder, "fifo")
        os.mkfifo(p)
        return p
    import _winapi
    import secrets
    name = "\\\\.\\pipe\\cra-test-" + secrets.token_hex(8)
    # PIPE_ACCESS_DUPLEX 3; PIPE_TYPE_BYTE | PIPE_WAIT 0; PIPE_UNLIMITED_INSTANCES 255 (_winapi names only some of them)
    handles = [_winapi.CreateNamedPipe(name, 3, 0, 255, 65536, 65536, 0, 0) for _ in range(64)]
    test.addCleanup(lambda: [_winapi.CloseHandle(h) for h in handles])
    return name
