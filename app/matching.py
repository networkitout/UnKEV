"""Deterministic matching of intel and inventory to catalog components."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


@dataclass
class _Comp:
    id: str
    alias_re: re.Pattern | None
    cpes: set[str]
    kev: list[tuple[re.Pattern, re.Pattern]]
    sw: list[re.Pattern]
    os: list[re.Pattern]


@dataclass
class Matcher:
    components: dict[str, dict]
    prefilter_terms: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._c: list[_Comp] = []
        for cid, c in self.components.items():
            aliases = c.get("aliases") or []
            alias_re = None
            if aliases:
                alias_re = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(a) for a in aliases) + r")(?![\w-])", re.I)
            inv = c.get("inventory") or {}
            self._c.append(_Comp(
                id=cid,
                alias_re=alias_re,
                cpes={x.lower() for x in c.get("cpe") or []},
                kev=[(re.compile(v, re.I), re.compile(p, re.I)) for v, p in c.get("kev") or []],
                sw=[re.compile(x, re.I) for x in inv.get("software") or []],
                os=[re.compile(x, re.I) for x in inv.get("os") or []],
            ))
        terms = [re.escape(t) for t in self.prefilter_terms]
        self._prefilter = re.compile(r"\b(" + "|".join(terms) + r")\b", re.I) if terms else None

    def match_text(self, text: str) -> list[str]:
        return [c.id for c in self._c if c.alias_re and c.alias_re.search(text or "")]

    def match_cpe(self, criteria: str) -> list[str]:
        # cpe:2.3:a:vendor:product:version:...
        parts = (criteria or "").lower().split(":")
        if len(parts) < 5:
            return []
        vp = f"{parts[3]}:{parts[4]}"
        return [c.id for c in self._c if vp in c.cpes]

    def match_kev(self, vendor: str, product: str) -> list[str]:
        return [c.id for c in self._c
                if any(v.search(vendor or "") and p.search(product or "") for v, p in c.kev)]

    def match_software(self, name: str) -> list[str]:
        return [c.id for c in self._c if any(r.search(name or "") for r in c.sw)]

    def match_os(self, os_str: str) -> list[str]:
        return [c.id for c in self._c if any(r.search(os_str or "") for r in c.os)]

    def passes_prefilter(self, text: str) -> bool:
        if CVE_RE.search(text or ""):
            return True
        if self.match_text(text):
            return True
        return bool(self._prefilter and self._prefilter.search(text or ""))
