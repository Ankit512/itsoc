#!/usr/bin/env python3
"""Universal UDP Syslog collector for UDP 513/514/1514.

- Concurrent listeners on multiple UDP ports.
- RFC3164 and RFC5424 PRI parsing when present.
- RFC3164/RFC5424 envelope hostname parsing (RFC3164 via the SAME regex the
  file pipeline uses — normalize.RFC3164_RE). `host` is the origin host the
  envelope asserts; the sender address is used ONLY when the envelope names
  none, and `host_source` records which one it was ("envelope" / "sender-ip"),
  so a relay's address is never silently presented as the origin.
- Preserves the original message verbatim.
- Stores events through console.store.insert_event when available.
- Bounded in-memory counters; no unbounded message list.
- Safe lifecycle: start/stop/restart and honest bind errors.
"""
from __future__ import annotations

import re
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from normalize import RFC3164_RE  # noqa: E402  # the file pipeline's envelope regex

DEFAULT_PORTS = (513, 514, 1514)
MAX_DATAGRAM = 65535

_SEV = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}
_FAC = {
    0:"kern",1:"user",2:"mail",3:"daemon",4:"auth",5:"syslog",6:"lpr",7:"news",
    8:"uucp",9:"cron",10:"authpriv",11:"ftp",12:"ntp",13:"audit",14:"alert",
    15:"clock",16:"local0",17:"local1",18:"local2",19:"local3",20:"local4",21:"local5",
    22:"local6",23:"local7"
}
_PRI = re.compile(r"^<(\d{1,3})>(.*)$", re.S)
# RFC5424 header: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RFC5424 = re.compile(r"^(?:\d)\s+([^\s]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+|-)\s*(.*)$", re.S)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_syslog(data: bytes, src_ip: str, src_port: int, listen_port: int) -> dict:
    text = data.decode("utf-8", "replace").rstrip("\x00\r\n")
    facility = severity = None
    pri = None
    m = _PRI.match(text)
    body = text
    if m:
        try:
            pri = int(m.group(1))
            if 0 <= pri <= 191:
                facility = _FAC.get(pri // 8, str(pri // 8))
                severity = _SEV.get(pri % 8, "")
            body = m.group(2)
        except ValueError:
            pass

    host = ""
    app = ""
    msgid = ""
    message = body
    r = _RFC5424.match(body)
    if r:
        _ts, host, app, _procid, msgid, _sd, message = r.groups()
        if host == "-": host = ""
        if app == "-": app = ""
        if msgid == "-": msgid = ""
    else:
        # RFC3164: "Mmm dd HH:MM:SS HOSTNAME TAG: msg". On a relayed stream the
        # envelope hostname is the ORIGIN; the sender address is only the last
        # hop. A hostname-less line puts the process tag where the hostname
        # would be ("su:", "sshd[123]:") — a tag is never claimed as the host.
        m3 = RFC3164_RE.match(body)
        if m3:
            cand = m3.group("host")
            if cand != "-" and not (cand.endswith(":") or "[" in cand or "(" in cand):
                host = cand

    return {
        "ts": _now(),
        "source": f"udp:{listen_port}",
        "source_type": "syslog:udp",
        "category": "syslog",
        "host": host or src_ip,
        # Honest fallback provenance: "sender-ip" means the envelope named no
        # origin, so host above is the sending address (possibly a relay).
        "host_source": "envelope" if host else "sender-ip",
        "src_ip": src_ip,
        "src_port": str(src_port),
        "dst_port": str(listen_port),
        "facility": facility or "",
        "priority": "" if pri is None else str(pri),
        "severity": severity or "",
        "application": app,
        "event_id": msgid,
        "action": "",
        "user": "",
        "message": message,
        "raw": text,
    }


class _Listener:
    def __init__(self, owner, port, bind):
        self.owner = owner
        self.port = int(port)
        self.bind = bind
        self.sock = None
        self.thread = None
        self.stop_event = threading.Event()
        self.received = 0
        self.stored = 0
        self.errors = 0
        self.last_error = ""
        self.last_source = ""
        self.last_message_at = ""

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind, self.port))
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._run, name=f"syslog-udp-{self.port}", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        s, self.sock = self.sock, None
        if s:
            try: s.close()
            except OSError: pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)

    def _run(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                self.errors += 1
                self.last_error = str(exc)
                continue
            try:
                event = parse_syslog(data, addr[0], addr[1], self.port)
                self.received += 1
                self.last_source = f"{addr[0]}:{addr[1]}"
                self.last_message_at = event["ts"]
                self.stored += self.owner._store(event)
            except Exception as exc:
                self.errors += 1
                self.last_error = str(exc)


class SyslogCollector:
    def __init__(self):
        self._lock = threading.RLock()
        self._listeners = {}
        self._last_error = ""

    @property
    def supported_ports(self):
        return list(DEFAULT_PORTS)

    def start(self, port=None, ports=None, bind="127.0.0.1"):
        if ports is None:
            ports = list(DEFAULT_PORTS) if port is None else [port]
        try:
            ports = sorted({int(p) for p in ports})
        except (TypeError, ValueError):
            return {"running": False, "error": "ports must be integers"}
        if not ports or any(p < 1 or p > 65535 for p in ports):
            return {"running": False, "error": "ports must be between 1 and 65535"}
        if bind not in ("127.0.0.1", "localhost", "0.0.0.0"):
            return {"running": False, "error": 'bind must be "127.0.0.1" or "0.0.0.0"'}
        bind = "127.0.0.1" if bind == "localhost" else bind
        with self._lock:
            # Idempotent for the same configuration.
            active = set(self._listeners)
            if active == set(ports) and all(l.thread and l.thread.is_alive() for l in self._listeners.values()):
                return self.status()
            self._stop_locked()
            started = {}
            try:
                for p in ports:
                    l = _Listener(self, p, bind)
                    l.start()
                    started[p] = l
            except OSError as exc:
                for l in started.values(): l.stop()
                self._listeners = {}
                self._last_error = self._bind_error(exc, p, bind)
                return self.status()
            self._listeners = started
            self._last_error = ""
            return self.status()

    def _bind_error(self, exc, port, bind):
        if getattr(exc, "errno", None) in (13,):
            return f"cannot bind UDP {port} on {bind}: permission denied; UDP ports below 1024 require appropriate privileges"
        if getattr(exc, "errno", None) in (98, 48, 10048):
            return f"cannot bind UDP {port} on {bind}: address already in use"
        return f"cannot bind UDP {port} on {bind}: {exc}"

    def _stop_locked(self):
        listeners = list(self._listeners.values())
        self._listeners = {}
        for l in listeners: l.stop()

    def stop(self):
        with self._lock:
            self._stop_locked()
            self._last_error = ""
            return self.status()

    def _store(self, event):
        try:
            import store
            if hasattr(store, "init_db"):
                store.init_db()
            if hasattr(store, "insert_event"):
                return 1 if store.insert_event(event) else 0
        except Exception as exc:
            self._last_error = f"store insert failed: {exc}"
        return 0

    def status(self):
        with self._lock:
            listeners = []
            for p in sorted(self._listeners):
                l = self._listeners[p]
                listeners.append({
                    "port": p,
                    "protocol": "UDP",
                    "bind": l.bind,
                    "running": bool(l.thread and l.thread.is_alive() and not l.stop_event.is_set()),
                    "received": l.received,
                    "stored": l.stored,
                    "errors": l.errors,
                    "lastError": l.last_error,
                    "lastSource": l.last_source,
                    "lastMessageAt": l.last_message_at,
                })
            return {
                "running": any(x["running"] for x in listeners),
                "protocol": "UDP",
                "supportedPorts": list(DEFAULT_PORTS),
                "ports": [x["port"] for x in listeners],
                "listeners": listeners,
                "error": self._last_error,
            }


COLLECTOR = SyslogCollector()
