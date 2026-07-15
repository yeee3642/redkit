"""Engagement state store.

A JSON-backed record of everything discovered during an engagement: hosts,
services, credentials, findings, and loot. No external database — a single
``engagement.json`` inside the workspace directory. This is the shared schema
every module reads from and writes to.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 1


class Engagement:
    """Mutable engagement state persisted as JSON.

    Data shape::

        {
          "schema": 1,
          "name": "op-foo",
          "created": 1700000000,
          "hosts": {
            "10.0.0.5": {
              "hostname": "dc01",
              "os": "Windows Server 2019",
              "ports": {
                "445/tcp": {"proto": "tcp", "port": 445, "service": "smb",
                             "product": "", "banner": "", "notes": []}
              },
              "tags": []
            }
          },
          "creds": [ {"service","host","username","password","hash","source"} ],
          "findings": [ {"id","title","severity","host","description","evidence"} ],
          "loot": [ {"host","kind","value","source"} ],
          "notes": [ {"ts","text"} ]
        }
    """

    def __init__(self, path: Path, data: Optional[Dict[str, Any]] = None):
        self.path = Path(path)
        self.data: Dict[str, Any] = data or self._empty(self.path.parent.name)

    # -- lifecycle ---------------------------------------------------------
    @staticmethod
    def _empty(name: str) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "name": name or "engagement",
            "created": int(time.time()),
            "hosts": {},
            "creds": [],
            "findings": [],
            "loot": [],
            "notes": [],
        }

    @classmethod
    def load_or_create(cls, path: Path) -> "Engagement":
        path = Path(path)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls(path, data)
            except (json.JSONDecodeError, OSError):
                pass
        eng = cls(path)
        eng.save()
        return eng

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    # -- hosts / services --------------------------------------------------
    def add_host(self, ip: str, hostname: Optional[str] = None, os_: Optional[str] = None) -> Dict[str, Any]:
        host = self.data["hosts"].setdefault(
            ip, {"hostname": None, "os": None, "ports": {}, "tags": []}
        )
        if hostname:
            host["hostname"] = hostname
        if os_:
            host["os"] = os_
        return host

    def add_service(
        self,
        ip: str,
        port: int,
        proto: str = "tcp",
        service: Optional[str] = None,
        product: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> Dict[str, Any]:
        host = self.add_host(ip)
        key = f"{port}/{proto}"
        svc = host["ports"].setdefault(
            key, {"proto": proto, "port": int(port), "service": None, "product": None, "banner": None, "notes": []}
        )
        if service:
            svc["service"] = service
        if product:
            svc["product"] = product
        if banner:
            svc["banner"] = banner
        return svc

    # -- creds / findings / loot ------------------------------------------
    def add_cred(
        self,
        service: str,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        secret_hash: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        entry = {
            "service": service,
            "host": host,
            "username": username,
            "password": password,
            "hash": secret_hash,
            "source": source,
        }
        if entry not in self.data["creds"]:
            self.data["creds"].append(entry)
        return entry

    def add_finding(
        self,
        title: str,
        severity: str = "info",
        host: Optional[str] = None,
        description: str = "",
        evidence: Optional[str] = None,
    ) -> Dict[str, Any]:
        fid = f"F-{len(self.data['findings']) + 1:03d}"
        entry = {
            "id": fid,
            "title": title,
            "severity": severity,
            "host": host,
            "description": description,
            "evidence": evidence,
        }
        self.data["findings"].append(entry)
        return entry

    def add_loot(self, host: Optional[str], kind: str, value: str, source: Optional[str] = None) -> Dict[str, Any]:
        entry = {"host": host, "kind": kind, "value": value, "source": source}
        self.data["loot"].append(entry)
        return entry

    def add_note(self, text: str) -> None:
        self.data["notes"].append({"ts": int(time.time()), "text": text})

    # -- queries -----------------------------------------------------------
    def hosts(self) -> Dict[str, Any]:
        return self.data["hosts"]

    def open_ports(self) -> List[Dict[str, Any]]:
        out = []
        for ip, host in self.data["hosts"].items():
            for key, svc in host["ports"].items():
                out.append({"ip": ip, "port": svc["port"], "proto": svc["proto"], "service": svc.get("service")})
        return out
