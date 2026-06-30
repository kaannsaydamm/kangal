# Kangal QA Report

- Generated: 2026-06-30 14:50:19
- Total checks: **76**
- PASS: **75** / FAIL: **0** / SKIP: **1**
- Total runtime: 116.7s

## Lab ortamı

| Servis | Port | Durum |
|---|---|---|
| nginx HTTP ana (8080) | 8080 | ✓ |
| nginx HTTP diğer (8001) | 8001 | ✓ |
| sshd | 2222 | ✓ |
| smbd (lab tuning'da sorunlu) | 445 | ✗ |
| TCP banner (fake vsftpd) | 31337 | ✓ |
| Kangal backend | 8000 | ✓ |
| Kangal frontend (Vite) | 5173 | ✓ |

## Bölüm bazında özet

| Bölüm | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| agents | 2 | 0 | 0 |
| boot | 2 | 0 | 1 |
| cli | 16 | 0 | 0 |
| engagement | 3 | 0 | 0 |
| frontend | 6 | 0 | 0 |
| intel | 9 | 0 | 0 |
| onboard | 4 | 0 | 0 |
| real-tools | 11 | 0 | 0 |
| redteam | 6 | 0 | 0 |
| ruflo | 9 | 0 | 0 |
| shell | 1 | 0 | 0 |
| system | 3 | 0 | 0 |
| toolbox | 3 | 0 | 0 |


### agents

- ✓ **scan start (POST /api/scan)** (21ms)
  - scan_id=5e44d55f-5c35-4f76-bac0-3ba16543b70d status=200
- ✓ **GET /api/scans** (13ms)
  - count=3

### boot

- ✓ **backend /api/intel/patterns 200** (42ms)
  - status=200 body={"patterns":[{"ts":1782819762.1520293,"agent":"subdomain","target":"scanme.test"
- ✓ **backend routes registered** (6ms)
  - route_count=50
- ~ **lab ports (partial)** (0ms)
  - up=['http_main', 'http_paths', 'ssh', 'tcp_vuln'] down=['smb'] — sadece aktif olanlar test edildi

### cli

- ✓ **CLI: --json scan list** (144ms)
  - exit=0 sample=[   {     "id": "5e44d55f-5c35-4f76-bac0-3ba16543b70d",     "target": "scanme.test",     "mode": "active",     "status":
- ✓ **CLI: --json intel patterns** (136ms)
  - exit=0 sample={   "patterns": [     {       "ts": 1782819762.1520293,       "agent": "subdomain",       "target": "scanme.test",      
- ✓ **CLI: --json engagement list** (137ms)
  - exit=0 sample={   "active": {     "eng-9af269a5ae": {       "id": "eng-9af269a5ae",       "name": "qa-engagement-1782819744",       "c
- ✓ **CLI: --json system diag** (1711ms)
  - exit=0 sample={   "host": {     "system": "Linux",     "release": "6.18.33.1-microsoft-standard-WSL2",     "machine": "x86_64",     "p
- ✓ **CLI: --json toolbox summary** (132ms)
  - exit=0 sample={   "total": 106,   "by_tier": {     "1": 67,     "2": 39   },   "by_category": {     "network_recon": 4,     "subdomain
- ✓ **CLI: --json tool list** (139ms)
  - exit=0 sample={   "tools": [     {       "name": "nmap",       "tier": 1,       "category": "network_recon",       "binary": "nmap",  
- ✓ **CLI: --json shell sessions** (136ms)
  - exit=0 sample={   "sessions": [     {       "session_id": "1a19e25882a44ca3",       "cols": 80,       "rows": 24,       "created_at": 
- ✓ **CLI: --help** (103ms)
  - exit=0 sample=Usage: kangal [OPTIONS] COMMAND [ARGS]...    Kangal Dashboard CLI — drive the Kangal backend from your terminal.  Option
- ✓ **CLI: scan --help** (97ms)
  - exit=0 sample=Usage: kangal scan [OPTIONS] COMMAND [ARGS]...    Scan lifecycle: list / get / start / events.  Options:   --help  Show 
- ✓ **CLI: intel --help** (100ms)
  - exit=0 sample=Usage: kangal intel [OPTIONS] COMMAND [ARGS]...    Cross-scan intel store: search, patterns, memory.  Options:   --help 
- ✓ **CLI: tool --help** (99ms)
  - exit=0 sample=Usage: kangal tool [OPTIONS] COMMAND [ARGS]...    Toolbox: list, run, install, inspect.  Options:   --help  Show this me
- ✓ **CLI: engagement --help** (99ms)
  - exit=0 sample=Usage: kangal engagement [OPTIONS] COMMAND [ARGS]...    Engagement manager: scope guard, kill switch, panic.  Options:  
- ✓ **CLI: system --help** (101ms)
  - exit=0 sample=Usage: kangal system [OPTIONS] COMMAND [ARGS]...    Host capabilities, onboard wizard, install.  Options:   --help  Show
- ✓ **CLI: toolbox --help** (97ms)
  - exit=0 sample=Usage: kangal toolbox [OPTIONS] COMMAND [ARGS]...    Toolbox aggregate views.  Options:   --help  Show this message and 
- ✓ **CLI: shell --help** (102ms)
  - exit=0 sample=Usage: kangal shell [OPTIONS] COMMAND [ARGS]...    Interactive PTY-backed bash sessions.  Options:   --help  Show this m
- ✓ **CLI intel patterns → JSON parse** (135ms)
  - exit=0 stdout_len=3330

### engagement

- ✓ **POST /api/engagement** (6ms)
  - status=200
- ✓ **GET /api/engagement** (6ms)
  - count=0
- ✓ **POST /api/engagement/scope-check** (21ms)
  - in_scope=True reason=matched env scope

### frontend

- ✓ **frontend tab '/'** (6897ms)
  - text_chars=1588
- ✓ **frontend tab 'INTEL'** (8353ms)
  - text_chars=1554
- ✓ **frontend tab 'TOOL MGR'** (8338ms)
  - text_chars=1644
- ✓ **frontend tab 'REPORTS'** (8345ms)
  - text_chars=1765
- ✓ **frontend tab 'CLI'** (8342ms)
  - text_chars=1970
- ✓ **frontend tab 'THREAT'** (8404ms)
  - text_chars=1652

### intel

- ✓ **GET /api/intel/patterns** (7ms)
  - status=200 sample={"patterns":[{"ts":1782819762.1520293,"agent":"subdomain","target":"scanme.test","outcome":"ok (5.92s)","confidence":0.9
- ✓ **GET /api/intel/search?q=*** (6ms)
  - status=200 sample={"query":"*","results":[],"count":0}
- ✓ **GET /api/intel/search?q=apache** (7ms)
  - status=200 sample={"query":"apache","results":[],"count":0}
- ✓ **GET /api/threat-intel/feed** (8ms)
  - status=200 sample={"recent_cves":[{"id":"CVE-2011-0627","description":"Adobe Flash Player before 10.3.181.14 on Windows, Mac OS X, Linux, 
- ✓ **GET /api/threat-intel/cve/CVE-2024-3094** (7ms)
  - status=200 sample={"id":"CVE-2024-3094","description":"Malicious code was discovered in the upstream tarballs of xz, starting with version
- ✓ **GET /api/threat-intel/recent-cves?days=7&severity=critical** (8ms)
  - status=200 sample={"window_days":7,"severity":"CRITICAL","count":14,"cves":[{"id":"CVE-2015-5719","description":"app/Controller/TemplatesC
- ✓ **GET /api/threat-intel/mitre** (5ms)
  - status=404
- ✓ **GET /api/threat-intel/nist** (6ms)
  - status=404
- ✓ **GET /api/threat-intel/attack-patterns** (5ms)
  - status=404

### onboard

- ✓ **POST /api/onboard/reset** (3843ms)
  - status=200
- ✓ **GET /api/onboard/state** (4184ms)
  - step=choose
- ✓ **POST /api/onboard/choose-path skip** (3770ms)
  - status=200
- ✓ **POST /api/onboard/finish** (3685ms)
  - status=200

### real-tools

- ✓ **nmap 127.0.0.1** (100ms)
  - open_ports=['2222', '5173', '8000', '8001', '8080', '31337']
- ✓ **nmap -sV service detect** (6180ms)
  - services=[('2222', 'ssh', 'OpenSSH 10.2p1 Debian 5 (protocol 2.0)'), ('8080', 'http', 'nginx 1.30.1'), ('31337', 'Elite?', '1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :')]
- ✓ **nikto 127.0.0.1:8080** (6176ms)
  - returncode=0 stdout_lines=46
- ✓ **ffuf 127.0.0.1:8080** (130ms)
  - found=['/.env', '/login', '/admin', '/api/v1/users', '/phpinfo.php']
- ✓ **nuclei 127.0.0.1:8080 (info+low)** (32643ms)
  - returncode=0 findings_lines=19
- ✓ **hydra ssh 127.0.0.1** (399ms)
  - returncode=0 (1 attempt)
- ✓ **sqlmap 127.0.0.1:8080 (risk1 lvl1)** (940ms)
  - returncode=0
- ✓ **nc banner grab :31337** (3ms)
  - got_banner=b'220 (vsFTPd 2.3.4)\n'
- ✓ **curl HEAD http://127.0.0.1:8080** (5ms)
  - headers=HTTP/1.1 200 OK
Server: nginx/1.30.1
Date: Tue, 30 Jun 2026 11:49:26 GMT
Content-Type: text/plain
Content-Length: 31
Connection: keep-alive
X-Powered-By: PHP/5.4.16
Server: nginx/1.18.0 (Ubuntu)


- ✓ **curl HEAD http://127.0.0.1:8001** (4ms)
  - server=HTTP/1.1 200 OK
Server: nginx/1.30.1
Date: Tue, 30 Jun 2026 11:49:26 GMT
Content-Type: text/plain
Content-Length: 33
Connection: keep-alive
Server: Apache/2.2.15 (CentOS)


- ✓ **ssh 127.0.0.1:2222 banner** (65ms)
  - returncode=255

### redteam

- ✓ **POST /api/redteam/exploit-attempt** (8ms)
  - status=422 body={"detail":[{"type":"missing","loc":["body","scan_id"],"msg":"Field required","input":{"target":"127.
- ✓ **POST /api/redteam/credential** (6ms)
  - status=422 body={"detail":[{"type":"missing","loc":["body","scan_id"],"msg":"Field required","input":{"target":"127.
- ✓ **POST /api/redteam/lateral-path** (8ms)
  - status=422 body={"detail":[{"type":"missing","loc":["body","scan_id"],"msg":"Field required","input":{"target":"127.
- ✓ **POST /api/redteam/persistence** (6ms)
  - status=422 body={"detail":[{"type":"missing","loc":["body","scan_id"],"msg":"Field required","input":{"target":"127.
- ✓ **POST /api/redteam/c2-beacon** (5ms)
  - status=422 body={"detail":[{"type":"missing","loc":["body","scan_id"],"msg":"Field required","input":{"target":"127.
- ✓ **GET /api/redteam/mitre** (8ms)
  - status=200

### ruflo

- ✓ **GET /api/ruflo/summary** (7ms)
  - status=200
- ✓ **GET /api/ruflo/hooks/stats** (6ms)
  - status=200
- ✓ **GET /api/ruflo/memory/stats** (5ms)
  - status=200
- ✓ **GET /api/ruflo/memory/search?q=*** (6ms)
  - status=200
- ✓ **GET /api/ruflo/patterns** (6ms)
  - status=200
- ✓ **GET /api/ruflo/patterns/search?q=*** (6ms)
  - status=200
- ✓ **GET /api/ruflo/swarm/status** (6ms)
  - status=200
- ✓ **GET /api/ruflo/agents** (6ms)
  - status=200
- ✓ **GET /api/ruflo/neural/status** (6ms)
  - status=200

### shell

- ✓ **POST /api/shell/sessions** (11ms)
  - session_id=dd4ff89434fa41dc

### system

- ✓ **GET /api/system/diag** (2007ms)
  - status=200
- ✓ **GET /api/system/diag/nmap** (9ms)
  - status=200
- ✓ **GET /api/system/diag/nuclei** (59ms)
  - status=200

### toolbox

- ✓ **GET /api/toolbox/summary** (5ms)
  - total=106
- ✓ **GET /api/toolbox/tools?limit=200** (9ms)
  - count=106
- ✓ **GET /api/toolbox/categories** (6ms)
  - categories=44
