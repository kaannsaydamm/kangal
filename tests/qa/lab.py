"""QA Lab — izole lokal hedefler.

Hedefler (her şey 127.0.0.1):
  - 8080 : nginx HTTP honeypot (kangal-qa target v1)
  - 8001 : python http.server (path brute-honeypot)
  - 2222 : sshd (keyless)
  - 445  : smbd anonymous share "QA"
  - 31337: ncat tcp banner "vsftpd 2.3.4" sahtecilik

DNS stub dışarıdan çağrılmaz; agent self-DNS resolver kullanır.
"""
from __future__ import annotations
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

LAB_DIR = Path("/tmp/qa-lab")
PID_DIR = LAB_DIR / "pids"
LOG_DIR = LAB_DIR / "logs"
WWW_DIR = LAB_DIR / "www"
NGINX_DIR = LAB_DIR / "nginx"
SSH_DIR = LAB_DIR / "ssh"

PORTS = {
    "http_main":   8080,
    "http_paths":  8001,
    "ssh":         2222,
    "smb":         445,
    "tcp_vuln":    31337,
}

ETC_HOSTS_MARK = "# kangal-qa-lab"
HOSTS_LINES = [
    "127.0.0.1 target.test",
    "127.0.0.1 scanme.test",
    "127.0.0.1 internal.lab",
    "127.0.0.1 admin.target.test",
    "127.0.0.1 api.target.test",
    "127.0.0.1 dev.target.test",
]

def log(msg: str) -> None:
    print(f"[lab] {msg}", flush=True)

def _pid(pidfile: Path) -> int | None:
    try:
        return int(pidfile.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None

def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def wait_port(port: int, host: str = "127.0.0.1", timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1.0) as s:
                return True
        except OSError:
            time.sleep(0.15)
    return False

def ensure_dirs() -> None:
    for d in (LAB_DIR, PID_DIR, LOG_DIR, WWW_DIR, NGINX_DIR, SSH_DIR):
        d.mkdir(parents=True, exist_ok=True)

def patch_hosts(enable: bool) -> None:
    text = Path("/etc/hosts").read_text()
    lines = [ln for ln in text.splitlines() if ETC_HOSTS_MARK not in ln]
    new_text = "\n".join(lines).rstrip() + "\n"
    if enable:
        new_text += "\n".join(HOSTS_LINES) + f"  {ETC_HOSTS_MARK}\n"
    tmp = Path("/tmp/kangal-hosts.tmp")
    tmp.write_text(new_text)
    subprocess.run(["sudo", "-n", "cp", str(tmp), "/etc/hosts"], check=True, capture_output=True)
    log(f"/etc/hosts patched ({'ON' if enable else 'OFF'})")

# ---------- nginx ----------

NGINX_CONF = """\
worker_processes 1;
error_log {log}/nginx.log info;
pid {pid}/nginx.pid;
daemon on;
events {{ worker_connections 64; }}
http {{
    access_log {log}/nginx-access.log;
    sendfile off;
    server {{
        listen 127.0.0.1:{p1};
        server_name _;
        default_type text/plain;
        add_header X-Powered-By "PHP/5.4.16" always;
        add_header Server "nginx/1.18.0 (Ubuntu)" always;
        location / {{ return 200 "kangal-qa target v1\\nnginx/1.18\\n"; }}
        location /admin/ {{ return 403 "Forbidden\\n"; }}
        location /api/v1/users {{
            default_type application/json;
            return 200 '[{{"id":1,"username":"admin","role":"root"}},{{"id":2,"username":"qa","role":"user"}}]';
        }}
        location /phpinfo.php {{ return 200 "PHP Version 5.4.16\\n"; }}
        location /login {{
            if ($request_method = POST) {{ return 200 "logged in\\n"; }}
            return 200 "login form\\n";
        }}
        location = /.env {{ return 200 "DB_HOST=localhost\\nDB_USER=root\\nDB_PASS=root\\n"; }}
    }}
    server {{
        listen 127.0.0.1:{p2};
        server_name _;
        default_type text/plain;
        add_header Server "Apache/2.2.15 (CentOS)" always;
        root {www};
        location / {{ return 200 "old squirrelmail reissue v1.4.22\\n"; }}
        location /webmail/ {{ try_files $uri /webmail/index.html; }}
    }}
}}
"""

def start_nginx() -> bool:
    (WWW_DIR / "index.html").write_text("<h1>kangal-qa target</h1>")
    (WWW_DIR / "webmail").mkdir(exist_ok=True)
    (WWW_DIR / "webmail" / "index.html").write_text("<h1>SquirrelMail reissue</h1>")
    # Use sudo to truncate old logs to root (worker can append if mode 666)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for f in ("nginx.log", "nginx-access.log"):
        path = LOG_DIR / f
        # Reset ownership to kaan if previously created as root
        if path.exists():
            subprocess.run(["sudo", "-n", "chown", "kaan:kaan", str(path)],
                           capture_output=True)
        else:
            path.touch()
        subprocess.run(["sudo", "-n", "chmod", "666", str(path)], capture_output=True)
    conf = NGINX_DIR / "nginx.conf"
    conf.write_text(NGINX_CONF.format(log=str(LOG_DIR), pid=str(PID_DIR), www=str(WWW_DIR),
                                       p1=PORTS["http_main"], p2=PORTS["http_paths"]))
    subprocess.run(["sudo", "-n", "nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
    res = subprocess.run(["sudo", "-n", "nginx", "-c", str(conf), "-p", str(LAB_DIR)],
                         capture_output=True, text=True)
    if res.returncode != 0:
        log(f"nginx start failed: {res.stderr[:300]}")
        return False
    time.sleep(0.5)
    pid_path = PID_DIR / "nginx.pid"
    if pid_path.exists():
        log(f"nginx pid={pid_path.read_text().strip()}")
    return wait_port(PORTS["http_main"]) and wait_port(PORTS["http_paths"])

# ---------- sshd ----------

SSHD_CONF = """\
Port {port}
ListenAddress 127.0.0.1
HostKey {ssh}/host_ed25519
PidFile {pid}/sshd.pid
PermitRootLogin no
AuthorizedKeysFile {ssh}/authorized_keys
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM no
StrictModes no
"""

def start_sshd() -> bool:
    if not (SSH_DIR / "host_ed25519").exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(SSH_DIR / "host_ed25519")],
                       check=True, capture_output=True)
    (SSH_DIR / "authorized_keys").write_text("")
    conf = SSH_DIR / "sshd.conf"
    conf.write_text(SSHD_CONF.format(port=PORTS["ssh"], ssh=str(SSH_DIR), pid=str(PID_DIR)))
    # kill any prior
    subprocess.run(["pkill", "-f", "sshd.*-f.*sshd.conf"], capture_output=True)
    res = subprocess.run(["sudo", "-n", "/usr/sbin/sshd", "-f", str(conf), "-E", str(LOG_DIR / "sshd.log")],
                         capture_output=True, text=True)
    if res.returncode != 0:
        log(f"sshd start failed: {res.stderr[:200]}")
        return False
    time.sleep(0.5)
    pid_p = PID_DIR / "sshd.pid"
    if pid_p.exists():
        log(f"sshd pid={pid_p.read_text().strip()}")
    return wait_port(PORTS["ssh"], timeout=8)

# ---------- smbd ----------

def start_smbd() -> bool:
    # /run/samba requires root for ncalrpc pipe directory; pre-create with permissive perms
    subprocess.run(["sudo", "-n", "mkdir", "-p", "/run/samba/ncalrpc/np"],
                   capture_output=True)
    subprocess.run(["sudo", "-n", "chmod", "1777", "/run/samba/ncalrpc"],
                   capture_output=True)
    subprocess.run(["sudo", "-n", "chmod", "755", "/run/samba/ncalrpc/np"],
                   capture_output=True)
    smb_log_dir = LAB_DIR / "smb-logs"
    smb_log_dir.mkdir(exist_ok=True)
    # reset log file to kaan-owned if existed
    for f in ("smbd.log",):
        path = smb_log_dir / f
        if path.exists():
            subprocess.run(["sudo", "-n", "chown", "kaan:kaan", str(path)],
                           capture_output=True)
        else:
            path.touch()
        subprocess.run(["sudo", "-n", "chmod", "666", str(path)], capture_output=True)
    private = LAB_DIR / "samba-private"
    private.mkdir(exist_ok=True)
    share_dir = LAB_DIR / "smb-share"
    share_dir.mkdir(exist_ok=True)
    (share_dir / "qa.txt").write_bytes(b"kangal-qa shares\n")
    conf = LAB_DIR / "smb.conf"
    conf.write_text(f"""\
[global]
workgroup = QA
private dir = {private}
lock directory = {private}/lock
state directory = {private}/state
cache directory = {private}/cache
log file = {smb_log_dir}/smbd.log
pid directory = {PID_DIR}
interfaces = lo
bind interfaces only = yes
smb ports = {PORTS['smb']}
disable netbios = yes
server min protocol = NT1
map to guest = bad user
guest account = nobody
passdb backend = tdbsam
[QA]
path = {share_dir}
read only = yes
guest ok = yes
browseable = yes
""")
    subprocess.run(["pkill", "-f", "smbd.*smb.conf"], capture_output=True)
    # Use sudo to launch as daemon (not -F foreground)
    res = subprocess.Popen(
        ["sudo", "-n", "smbd", "--configfile", str(conf)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    if res.poll() not in (None, 0):
        log(f"smbd daemon exited code={res.poll()}")
        return False
    return wait_port(PORTS["smb"], timeout=10)

# ---------- tcp banner (vsftpd fake) ----------

def start_tcp_banner() -> bool:
    banner = "220 (vsFTPd 2.3.4)\n"
    (LAB_DIR / "banner.txt").write_text(banner)
    subprocess.run(["pkill", "-f", "lab-stubs"], capture_output=True)
    # use python3 socket server with -k (handle one connection, exit) and serve from file
    # actually use a loop in shell via -c "while true; do nc -l ...":
    script = LAB_DIR / "banner_server.sh"
    script.write_text(f"""#!/bin/bash
exec /usr/bin/ncat.openbsd -lk 127.0.0.1 {PORTS["tcp_vuln"]} -c "cat /tmp/qa-lab/banner.txt"
""")
    # ncat.openbsd is BSD netcat on Kali — let's check
    if not Path("/usr/bin/ncat.openbsd").exists():
        # fallback: python loop server
        py = LAB_DIR / "banner_server.py"
        py.write_text(f"""#!/usr/bin/env python3
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', {PORTS["tcp_vuln"]}))
s.listen(8)
print('tcp banner on {PORTS["tcp_vuln"]}', flush=True)
while True:
    c, _ = s.accept()
    try:
        c.sendall(open('/tmp/qa-lab/banner.txt', 'rb').read())
    finally:
        c.close()
""")
        res = subprocess.Popen(["python3", str(py)],
                                stdout=open(LOG_DIR / "banner.log", "ab"),
                                stderr=subprocess.STDOUT)
        (PID_DIR / "tcp_banner.pid").write_text(str(res.pid))
        return wait_port(PORTS["tcp_vuln"])
    else:
        script.chmod(0o755)
        res = subprocess.Popen(["bash", str(script)],
                                stdout=open(LOG_DIR / "banner.log", "ab"),
                                stderr=subprocess.STDOUT)
        (PID_DIR / "tcp_banner.pid").write_text(str(res.pid))
        return wait_port(PORTS["tcp_vuln"])

# ---------- public ----------

def start_lab() -> None:
    ensure_dirs()
    patch_hosts(True)
    port_state = {}
    for label, fn in [
        ("http_main", start_nginx),
        ("ssh", start_sshd),
        ("smb", start_smbd),
        ("tcp_vuln", start_tcp_banner),
    ]:
        try:
            port_state[label] = fn()
        except Exception as e:
            log(f"  {label}: exception {e}")
            port_state[label] = False
    port_state["http_paths"] = port_state["http_main"]  # second vhost in same nginx
    for n, ok in port_state.items():
        log(f"  {n} ({PORTS[n]}): {'OK' if ok else 'DOWN'}")

def stop_lab() -> None:
    for name in ("nginx", "sshd", "smbd", "tcp_banner"):
        pidfile = PID_DIR / f"{name}.pid"
        pid = _pid(pidfile)
        if pid and _alive(pid):
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except OSError:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
        try:
            pidfile.unlink()
        except FileNotFoundError:
            pass
    # Belt-and-braces: kill anything still bound to our ports
    subprocess.run(["bash", "-c",
        "for p in 8080 8001 2222 445 5353 31337; do fuser -k -q ${p}/tcp 2>/dev/null || true; done"
    ], capture_output=True)
    # kill any python http.server fallback
    subprocess.run(["pkill", "-f", "lab-fallback"], capture_output=True)
    patch_hosts(False)
    log("lab stopped")

def lab_health() -> dict:
    return {name: wait_port(p, timeout=1.0) for name, p in PORTS.items()}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "start"
    if cmd == "start":
        start_lab()
    elif cmd == "stop":
        stop_lab()
    elif cmd == "health":
        for n, ok in lab_health().items():
            print(f"  {n}: {'OK' if ok else 'DOWN'}")
