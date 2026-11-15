"""Blocklists: domain categories and destination-IP lists.

Local files under blocklists/builtin are always loaded. Remote lists are
downloaded into blocklists/cache (conditional GET, so refreshes are cheap) and
the in-memory matchers are rebuilt and swapped atomically, so filtering never
pauses during an update. If a download fails the last good copy keeps working.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import time
import urllib.request

from .config import resolve_path
from .iplist import IPSet, is_public

USER_AGENT = "parental-gateway/1.0 (+home network filter)"
_IP_KEYS = {"ipv4_addr_in", "ipv6_addr_in", "entryip", "exitip", "or_addresses",
            "ip", "ipv4", "ipv6", "address"}


class DomainMatcher:
    """A set of domains; a name matches if it equals an entry or is a subdomain of one."""

    def __init__(self):
        self._domains: set[str] = set()

    def add(self, domain: str) -> bool:
        d = domain.strip().lower().rstrip(".")
        if d.startswith("*."):
            d = d[2:]
        if d.startswith("||"):
            d = d[2:]
        d = d.rstrip("^")
        if not d or "." not in d or " " in d or "/" in d:
            return False
        if d in ("localhost", "localhost.localdomain", "broadcasthost", "local"):
            return False
        self._domains.add(d)
        return True

    def load_file(self, path: str | None) -> int:
        if not path or not os.path.exists(path):
            return 0
        n = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("!"):
                    continue
                parts = line.split()
                # hosts format "0.0.0.0 domain [domain...]" or a bare domain
                cands = parts[1:] if len(parts) > 1 and _looks_like_ip(parts[0]) else parts[:1]
                for c in cands:
                    n += self.add(c)
        return n

    def match(self, name: str) -> bool:
        d = name.lower().rstrip(".")
        if d in self._domains:
            return True
        i = d.find(".")
        while i != -1:
            if d[i + 1:] in self._domains:
                return True
            i = d.find(".", i + 1)
        return False

    def __len__(self):
        return len(self._domains)

    def domains(self):
        return self._domains


def _looks_like_ip(s: str) -> bool:
    return s.count(".") == 3 and s.replace(".", "").isdigit() or s in ("::", "::1") or ":" in s and s.startswith(("::", "fe80"))


def _extract_ips(obj, out: list):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in _IP_KEYS:
                vals = v if isinstance(v, list) else [v]
                for val in vals:
                    if isinstance(val, str):
                        out.append(_strip_port(val))
            else:
                _extract_ips(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _extract_ips(v, out)


def _strip_port(s: str) -> str:
    s = s.strip()
    if s.startswith("["):                  # [2001:db8::1]:443
        return s[1:s.index("]")] if "]" in s else s
    if s.count(":") == 1:                  # 1.2.3.4:9001
        return s.split(":")[0]
    return s


class ListManager:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.cache_dir = resolve_path(cfg, cfg.get("lists_cache_dir", "blocklists/cache"))
        os.makedirs(self.cache_dir, exist_ok=True)
        self.categories: dict[str, DomainMatcher] = {}
        self.ip_sets: dict[str, IPSet] = {}
        self.exempt = IPSet()
        self.cdn_guard = IPSet()
        self.status: dict[str, dict] = {}
        self.popular: set[str] = set()      # registrable domains of the world's most-visited sites
        self.version = 0
        self.last_update = 0.0
        self.updating = False
        self._lock = threading.Lock()
        self.resolve_fn = None          # set by the app: name -> [ips], used for pinning

    # ------------------------------------------------------------ helpers
    def _cache_path(self, url: str) -> str:
        return os.path.join(self.cache_dir, hashlib.sha1(url.encode()).hexdigest()[:16] + ".txt")

    def _meta_path(self, url: str) -> str:
        return self._cache_path(url)[:-4] + ".json"

    def _read_meta(self, url):
        try:
            with open(self._meta_path(url), "r") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _write_meta(self, url, meta):
        with open(self._meta_path(url), "w") as fh:
            json.dump(meta, fh)

    # ------------------------------------------------------------ loading
    def load(self):
        """(Re)build all matchers from builtin files + cached downloads."""
        cats, status = {}, {}
        for name, spec in (self.cfg.get("categories") or {}).items():
            m = DomainMatcher()
            srcs = []
            for f in spec.get("files") or []:
                p = resolve_path(self.cfg, f)
                n = m.load_file(p)
                srcs.append({"source": f, "entries": n, "ok": os.path.exists(p)})
            for url in spec.get("urls") or []:
                n = m.load_file(self._cache_path(url))
                meta = self._read_meta(url)
                srcs.append({"source": url, "entries": n, "ok": meta.get("ok", n > 0),
                             "error": meta.get("error"), "fetched": meta.get("fetched")})
            cats[name] = m
            status[f"category:{name}"] = {"kind": "domains", "entries": len(m), "sources": srcs}

        ipsets = {}
        for name, spec in (self.cfg.get("ip_lists") or {}).items():
            s = IPSet()
            srcs = []
            for f in spec.get("files") or []:
                p = resolve_path(self.cfg, f)
                n = self._load_ip_file(s, p)
                srcs.append({"source": f, "entries": n, "ok": os.path.exists(p)})
            for src in spec.get("sources") or []:
                url = src["url"]
                n = self._load_ip_file(s, self._cache_path(url))
                meta = self._read_meta(url)
                srcs.append({"source": url, "entries": n, "ok": meta.get("ok", n > 0),
                             "error": meta.get("error"), "fetched": meta.get("fetched")})
            if spec.get("pin_domains"):
                pin_cache = os.path.join(self.cache_dir, f"pins-{name}.txt")
                n = self._load_ip_file(s, pin_cache)
                srcs.append({"source": f"pinned IPs of {spec['pin_domains']}", "entries": n,
                             "ok": n > 0})
            s.finalize()
            ipsets[name] = s
            status[f"ips:{name}"] = {"kind": "ips", "entries": len(s), "sources": srcs}

        exempt = IPSet()
        self._load_ip_file(exempt, resolve_path(self.cfg, (self.cfg.get("enforcement") or {})
                                                 .get("consistency_exempt")))
        exempt.finalize()
        guard = IPSet()
        self._load_ip_file(guard, resolve_path(self.cfg, "blocklists/builtin/cdn-guard.txt"))
        guard.finalize()

        popular, psrc = set(), []
        rep = self.cfg.get("reputation") or {}
        for f in rep.get("popularity_files") or []:
            n = self._load_domains(popular, resolve_path(self.cfg, f))
            psrc.append({"source": f, "entries": n, "ok": n > 0})
        for url in rep.get("popularity_urls") or []:
            n = self._load_domains(popular, self._cache_path(url))
            meta = self._read_meta(url)
            psrc.append({"source": url, "entries": n, "ok": meta.get("ok", n > 0),
                         "error": meta.get("error"), "fetched": meta.get("fetched")})
        status["popular:sites"] = {"kind": "domains", "entries": len(popular), "sources": psrc}

        with self._lock:
            self.categories, self.ip_sets, self.status = cats, ipsets, status
            self.exempt, self.cdn_guard = exempt, guard
            self.popular = popular
            self.version += 1

    @staticmethod
    def _load_domains(out: set, path: str | None) -> int:
        if not path or not os.path.exists(path):
            return 0
        n = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                d = line.strip().lower()
                if d and not d.startswith("#"):
                    out.add(d)
                    n += 1
        return n

    def _parse_popularity(self, body: bytes, top: int) -> list[str]:
        """Tranco / Umbrella style 'rank,domain' CSV (optionally zipped) -> registrable domains."""
        from .services import registrable_domain
        if body[:2] == b"PK":
            import zipfile
            z = zipfile.ZipFile(io.BytesIO(body))
            body = z.read(z.namelist()[0])
        out, seen = [], set()
        for i, line in enumerate(body.decode("utf-8", "ignore").splitlines()):
            if i >= top:
                break
            parts = line.strip().split(",")
            name = parts[-1].strip().lower() if parts else ""
            reg = registrable_domain(name)
            if reg and "." in reg and reg not in seen:
                seen.add(reg)
                out.append(reg)
        return out

    @staticmethod
    def _load_ip_file(s: IPSet, path: str | None) -> int:
        if not path or not os.path.exists(path):
            return 0
        n = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                n += s.add(line.split("#", 1)[0])
        return n

    # ------------------------------------------------------------ downloading
    def _fetch(self, url: str) -> bytes | None:
        meta = self._read_meta(url)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        if meta.get("etag") and os.path.exists(self._cache_path(url)):
            req.add_header("If-None-Match", meta["etag"])
        if meta.get("last_modified") and os.path.exists(self._cache_path(url)):
            req.add_header("If-Modified-Since", meta["last_modified"])
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read()
                meta.update({"etag": resp.headers.get("ETag"),
                             "last_modified": resp.headers.get("Last-Modified"),
                             "fetched": time.time(), "ok": True, "error": None})
                self._write_meta(url, meta)
                return body
        except urllib.error.HTTPError as e:
            if e.code == 304:
                meta.update({"fetched": time.time(), "ok": True, "error": None})
                self._write_meta(url, meta)
                return None
            meta.update({"ok": False, "error": f"HTTP {e.code}"})
        except Exception as e:
            meta.update({"ok": False, "error": str(e)[:200]})
        self._write_meta(url, meta)
        return None

    def _store(self, url: str, text: str):
        tmp = self._cache_path(url) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, self._cache_path(url))

    def update(self):
        """Download every remote list, re-pin domains, then rebuild."""
        self.updating = True
        try:
            for spec in (self.cfg.get("categories") or {}).values():
                for url in spec.get("urls") or []:
                    body = self._fetch(url)
                    if body:
                        self._store(url, body.decode("utf-8", "ignore"))
            rep = self.cfg.get("reputation") or {}
            for url in rep.get("popularity_urls") or []:
                body = self._fetch(url)
                if body:
                    doms = self._parse_popularity(body, int(rep.get("popular_top", 200000)))
                    if doms:
                        self._store(url, "\n".join(doms) + "\n")
            for name, spec in (self.cfg.get("ip_lists") or {}).items():
                for src in spec.get("sources") or []:
                    body = self._fetch(src["url"])
                    if body:
                        ips = self._parse_ip_source(src.get("type", "cidr"), body)
                        if ips:
                            self._store(src["url"], "\n".join(ips) + "\n")
                        else:
                            meta = self._read_meta(src["url"])
                            meta.update({"ok": False, "error": "no IPs found in response"})
                            self._write_meta(src["url"], meta)
                if spec.get("pin_domains"):
                    self._pin(name, resolve_path(self.cfg, spec["pin_domains"]))
            self.load()
            self.last_update = time.time()
        finally:
            self.updating = False

    def _parse_ip_source(self, kind: str, body: bytes) -> list[str]:
        text = body.decode("utf-8", "ignore")
        raw: list[str] = []
        if kind == "cidr":
            raw = [l.split("#", 1)[0].strip() for l in text.splitlines()]
        else:                                         # mullvad / proton / tor / json
            try:
                _extract_ips(json.loads(text), raw)
            except ValueError:
                return []
        out = []
        tmp = IPSet()
        for r in raw:
            if not r:
                continue
            host = r.split("/")[0]
            if "/" not in r and not is_public(host):
                continue
            if host in self.cdn_guard:                # never block shared CDN space by accident
                continue
            if tmp.add(r):
                out.append(r)
        return out

    def _pin(self, name: str, pin_file: str | None):
        """Resolve VPN/DoH API hostnames and remember their IPs, so a client
        with a hard-coded IP for them is still blocked."""
        if not pin_file or not os.path.exists(pin_file) or not self.resolve_fn:
            return
        ips = set()
        with open(pin_file, "r") as fh:
            for line in fh:
                d = line.split("#", 1)[0].strip()
                if not d:
                    continue
                try:
                    for ip in self.resolve_fn(d):
                        if is_public(ip) and ip not in self.cdn_guard:
                            ips.add(ip)
                except Exception:
                    pass
        if ips:
            path = os.path.join(self.cache_dir, f"pins-{name}.txt")
            with open(path, "w") as fh:
                fh.write("\n".join(sorted(ips)) + "\n")

    def start_background(self, initial_delay: float = 2.0):
        hours = float(self.cfg.get("lists_refresh_hours", 24))

        def loop():
            time.sleep(initial_delay)
            while True:
                try:
                    self.update()
                    print(f"[lists] updated: " + ", ".join(
                        f"{k}={v['entries']}" for k, v in self.status.items()))
                except Exception as e:
                    print(f"[lists] update failed: {e}")
                time.sleep(max(1.0, hours) * 3600)

        threading.Thread(target=loop, name="lists", daemon=True).start()

    # ------------------------------------------------------------ queries
    def category_match(self, name: str, categories) -> str | None:
        cats = self.categories
        for c in categories:
            m = cats.get(c)
            if m is not None and m.match(name):
                return c
        return None

    def ip_list_match(self, ip: str) -> str | None:
        for name, s in self.ip_sets.items():
            if ip in s:
                return name
        return None
