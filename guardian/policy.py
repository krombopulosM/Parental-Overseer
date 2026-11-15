"""Decide whether a given client's DNS lookup should be allowed or blocked.

Order of precedence:
  1. explicit 'allow' rule  -> allow  (lets you whitelist one site inside a blocked category)
  2. explicit 'block' rule   -> block
  3. category blocklist for the device's group -> block
  4. otherwise -> allow
"""
import os


class DomainMatcher:
    """Set of domains; matches a name exactly or as a subdomain of an entry."""

    def __init__(self):
        self._domains = set()

    def add(self, domain):
        d = domain.lower().strip().rstrip(".")
        if d:
            self._domains.add(d)

    def load_file(self, path):
        if not path or not os.path.exists(path):
            return 0
        n = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # accept "0.0.0.0 domain", "127.0.0.1 domain", or bare "domain"
                domain = line.split()[-1]
                if domain in ("localhost", "localhost.localdomain", "broadcasthost"):
                    continue
                self.add(domain)
                n += 1
        return n

    def matches(self, qname):
        d = qname.lower().rstrip(".")
        if d in self._domains:
            return True
        labels = d.split(".")
        for i in range(1, len(labels)):
            if ".".join(labels[i:]) in self._domains:
                return True
        return False


class Decision:
    __slots__ = ("block", "reason")

    def __init__(self, block, reason):
        self.block = block
        self.reason = reason


class Policy:
    def __init__(self, db, cfg):
        self.db = db
        self.categories = {}   # name -> (DomainMatcher, set(groups))
        base = cfg.get("__base__", ".")
        for name, spec in (cfg.get("categories") or {}).items():
            matcher = DomainMatcher()
            path = spec.get("file")
            if path and not os.path.isabs(path):
                path = os.path.join(base, path)
            count = matcher.load_file(path)
            groups = set(spec.get("groups") or [])
            self.categories[name] = (matcher, groups)
            print(f"[policy] category '{name}': {count} domains -> groups {sorted(groups)}")

    def decide(self, client_ip, qname):
        group = self.db.get_group(client_ip)
        rules = self.db.rules_for(client_ip, group)

        for r in rules:                                    # 1. explicit allow
            if r["action"] == "allow" and self._match(r["pattern"], qname):
                return Decision(False, f"allow rule: {r['pattern']}")
        for r in rules:                                    # 2. explicit block
            if r["action"] == "block" and self._match(r["pattern"], qname):
                return Decision(True, f"block rule: {r['pattern']}")
        for name, (matcher, groups) in self.categories.items():   # 3. category
            if group in groups and matcher.matches(qname):
                return Decision(True, f"category: {name}")
        return Decision(False, "")                         # 4. allow

    @staticmethod
    def _match(pattern, qname):
        d = qname.lower().rstrip(".")
        p = pattern.lower().rstrip(".")
        return d == p or d.endswith("." + p)
