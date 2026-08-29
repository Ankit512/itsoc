#!/usr/bin/env python3
"""Universal Syslog collector for UDP/TCP 514/1514.

- Concurrent UDP and TCP listeners on multiple ports.
- RFC 6587 TCP framing: octet-counting and non-transparent (LF-delimited).
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

import collections
import re
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from normalize import RFC3164_RE  # noqa: E402  # the file pipeline's envelope regex
import store  # noqa: E402  # imported once; schema is initialized once per start

DEFAULT_PORTS = (514, 1514)
MAX_DATAGRAM = 65535
MAX_TCP_BUFFER = MAX_DATAGRAM * 2
# Bounded in-memory queue between the listeners and the synchronous SQLite
# writer. A listener must never block on disk: a UDP listener stuck in a write
# lets the kernel receive buffer overflow and drop datagrams that NOTHING
# counts, and a drop nobody counts is indistinguishable from an event that never
# happened. So listeners offer() non-blocking to this queue and a drain worker
# does the writes; a full queue drops the incoming event and COUNTS the drop,
# turning an invisible kernel drop into a counted, surfaced one.
INGEST_QUEUE_LIMIT = 10000

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


def parse_syslog(data: bytes, src_ip: str, src_port: int, listen_port: int,
                 protocol: str = "udp") -> dict:
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
        "source": f"{protocol}:{listen_port}",
        "source_type": f"syslog:{protocol}",
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


class _IngestQueue:
    """Bounded buffer between the syslog listeners and the SQLite writer,
    modelled on serve.StreamQueue.

    Listeners offer() non-blocking; a single drain worker writes to the store.
    When the writer cannot keep up the queue fills and offer() REFUSES the event
    and counts it (``dropped``) rather than blocking the listener — a silent drop
    would fake a quiet network, which this repo forbids. ``lagging`` is the live
    backlog depth (how far the writer is behind); ``ingested`` is what actually
    reached the store. All three are surfaced by SyslogCollector.status().
    """

    def __init__(self, limit=None):
        self.limit = int(limit or INGEST_QUEUE_LIMIT)
        self._items = collections.deque()
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._closed = False
        self.ingested = 0    # events the drain worker wrote to the store
        self.dropped = 0     # events lost: queue full (back-pressure) or store failure
        self.high_water = 0  # deepest backlog ever observed (lag high-water mark)

    def offer(self, event):
        """Non-blocking enqueue. True if queued; False (and COUNTED) if full."""
        with self._lock:
            if self._closed:
                return False
            if len(self._items) >= self.limit:
                self.dropped += 1
                return False
            self._items.append(event)
            depth = len(self._items)
            if depth > self.high_water:
                self.high_water = depth
            self._ready.set()
            return True

    def take(self, timeout):
        """Block up to ``timeout`` for one event; None on timeout/empty/close."""
        if not self._ready.wait(timeout):
            return None
        with self._lock:
            item = self._items.popleft() if self._items else None
            if not self._items:
                self._ready.clear()
            return item

    def record_ingested(self):
        with self._lock:
            self.ingested += 1

    def record_store_failure(self):
        with self._lock:
            self.dropped += 1

    def depth(self):
        with self._lock:
            return len(self._items)

    def close(self):
        with self._lock:
            self._closed = True
            self._ready.set()


class _BaseListener:
    protocol = ""

    def __init__(self, owner, port, bind):
        self.owner = owner
        self.port = int(port)
        self.bind = bind
        self.sock = None
        self.thread = None
        self.stop_event = threading.Event()
        self.received = 0
        self.errors = 0
        self.last_error = ""
        self.last_source = ""
        self.last_message_at = ""

    def stop(self):
        self.stop_event.set()
        s, self.sock = self.sock, None
        if s:
            try: s.close()
            except OSError: pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.5)

    def _record(self, data, addr):
        event = parse_syslog(data, addr[0], addr[1], self.port, self.protocol.lower())
        self.received += 1
        self.last_source = f"{addr[0]}:{addr[1]}"
        self.last_message_at = event["ts"]
        # Non-blocking hand-off: never block the listener on disk. A full queue
        # counts the drop (owner._queue.dropped) instead of losing it silently.
        self.owner._offer(event)

    def _error(self, exc):
        self.errors += 1
        self.last_error = str(exc)


class _UDPListener(_BaseListener):
    protocol = "UDP"

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # UDP has no TIME_WAIT. SO_REUSEADDR can let another local process bind
        # the same port and split the event stream, so exclusive bind is safer.
        self.sock.bind((self.bind, self.port))
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._run, name=f"syslog-udp-{self.port}", daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                self._error(exc)
                continue
            try:
                self._record(data, addr)
            except Exception as exc:
                self._error(exc)


class _TCPListener(_BaseListener):
    protocol = "TCP"

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TCP restart needs address reuse because closed connections enter
        # TIME_WAIT; unlike UDP, this does not split datagrams between sockets.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind, self.port))
        self.sock.listen(32)
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._run, name=f"syslog-tcp-{self.port}", daemon=True)
        self.thread.start()

    def _run(self):
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                self._error(exc)
                continue
            threading.Thread(target=self._client, args=(conn, addr),
                             name=f"syslog-tcp-client-{self.port}", daemon=True).start()

    def _client(self, conn, addr):
        buffer = b""
        with conn:
            conn.settimeout(0.5)
            while not self.stop_event.is_set():
                try:
                    chunk = conn.recv(MAX_DATAGRAM)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buffer += chunk
                try:
                    frames, buffer = self._frames(buffer, final=False)
                    for frame in frames:
                        self._record(frame, addr)
                except ValueError as exc:
                    self._error(exc)
                    return
            try:
                frames, _ = self._frames(buffer, final=True)
                for frame in frames:
                    self._record(frame, addr)
            except ValueError as exc:
                self._error(exc)

    @staticmethod
    def _frames(buffer, final=False):
        """Extract RFC 6587 octet-counted or LF-delimited frames from bytes."""
        frames = []
        while buffer:
            prefix = re.match(br"^(\d+) ", buffer)
            if prefix:
                length = int(prefix.group(1))
                if length > MAX_DATAGRAM:
                    raise ValueError(f"RFC6587 frame exceeds {MAX_DATAGRAM} bytes")
                start = prefix.end()
                if len(buffer) - start < length:
                    if len(buffer) > MAX_TCP_BUFFER:
                        raise ValueError("RFC6587 receive buffer limit exceeded")
                    break
                frame, buffer = buffer[start:start + length], buffer[start + length:]
                if frame:
                    frames.append(frame)
                continue
            newline = buffer.find(b"\n")
            if newline >= 0:
                frame, buffer = buffer[:newline].rstrip(b"\r"), buffer[newline + 1:]
                if frame:
                    frames.append(frame)
                continue
            if len(buffer) > MAX_TCP_BUFFER:
                raise ValueError("RFC6587 receive buffer limit exceeded")
            if final and buffer.rstrip(b"\r"):
                frames.append(buffer.rstrip(b"\r"))
                buffer = b""
            break
        return frames, buffer


class SyslogCollector:
    def __init__(self):
        self._lock = threading.RLock()
        self._listeners = {}
        self._last_error = ""
        self._last_bind = "127.0.0.1"
        self._last_port = 1514
        self._started_at = None
        # Bounded ingest queue + single drain worker (created on start()).
        self._queue = None
        self._worker = None
        self._worker_stop = threading.Event()

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
            self._last_bind = bind
            self._last_port = ports[0] if ports else 1514
            # Idempotent for the same configuration.
            wanted = {(proto, p) for p in ports for proto in ("udp", "tcp")}
            active = set(self._listeners)
            if active == wanted and all(l.thread and l.thread.is_alive() for l in self._listeners.values()):
                return self.status()
            self._stop_locked()
            started = {}
            try:
                store.init_db()
                # Bring the queue + drain worker up BEFORE any listener, so a
                # datagram that arrives during startup is queued, never dropped.
                self._start_worker_locked()
                for p in ports:
                    for proto, listener_type in (("udp", _UDPListener), ("tcp", _TCPListener)):
                        l = listener_type(self, p, bind)
                        l.start()
                        started[(proto, p)] = l
            except Exception as exc:
                for l in started.values(): l.stop()
                self._stop_worker_locked()
                self._listeners = {}
                self._last_error = (self._bind_error(exc, p, bind)
                                    if isinstance(exc, OSError)
                                    else f"cannot initialize syslog store: {exc}")
                self._started_at = None
                return self.status()
            self._listeners = started
            self._started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._last_error = ""
            return self.status()

    def _bind_error(self, exc, port, bind):
        if getattr(exc, "errno", None) in (13,):
            return f"cannot bind syslog port {port} on {bind}: permission denied; ports below 1024 require appropriate privileges"
        if getattr(exc, "errno", None) in (98, 48, 10048):
            return f"cannot bind syslog port {port} on {bind}: address already in use"
        return f"cannot bind syslog port {port} on {bind}: {exc}"

    def _stop_locked(self):
        listeners = list(self._listeners.values())
        self._listeners = {}
        self._started_at = None
        for l in listeners: l.stop()
        self._stop_worker_locked()

    def stop(self):
        with self._lock:
            self._stop_locked()
            self._last_error = ""
            return self.status()

    # --- bounded ingest queue + drain worker -------------------------------
    def _offer(self, event):
        """Non-blocking hand-off from a listener to the drain worker. Returns
        False (and the queue counts a drop) when the queue is full or absent."""
        q = self._queue
        return q.offer(event) if q is not None else False

    def _start_worker_locked(self):
        self._worker_stop = threading.Event()
        self._queue = _IngestQueue()
        self._worker = threading.Thread(target=self._drain, args=(self._queue,),
                                        name="syslog-ingest-drain", daemon=True)
        self._worker.start()

    def _stop_worker_locked(self):
        self._worker_stop.set()
        q = self._queue
        if q is not None:
            q.close()
        w = self._worker
        self._worker = None
        self._queue = None
        if w and w.is_alive():
            w.join(timeout=1.5)

    def _drain(self, q):
        """The ONLY thread that writes to the store. A truthy insert is an
        ingest; a falsy return is a legitimate dedupe (not a drop); an exception
        is a real store failure and IS counted as a drop — so a SQLite lock under
        burst load can never vanish silently."""
        while not self._worker_stop.is_set():
            event = q.take(0.5)
            if event is None:
                continue
            try:
                if store.insert_event(event):
                    q.record_ingested()
            except Exception as exc:
                q.record_store_failure()
                self._last_error = f"store insert failed: {exc}"

    def status(self):
        with self._lock:
            listeners = []
            for key in sorted(self._listeners, key=lambda x: (x[1], x[0])):
                l = self._listeners[key]
                listeners.append({
                    "port": l.port,
                    "protocol": l.protocol,
                    "bind": l.bind,
                    "running": bool(l.thread and l.thread.is_alive() and not l.stop_event.is_set()),
                    "received": l.received,
                    "errors": l.errors,
                    "lastError": l.last_error,
                    "lastSource": l.last_source,
                    "lastMessageAt": l.last_message_at,
                })
            running = any(x["running"] for x in listeners)
            first_l = listeners[0] if listeners else None
            bind_val = first_l["bind"] if first_l else self._last_bind
            port_val = first_l["port"] if first_l else self._last_port
            started_at = self._started_at if running else None
            last_events = [x["lastMessageAt"] for x in listeners if x["lastMessageAt"]]
            last_event_at = max(last_events) if last_events else None

            # Back-pressure accounting, owned by the ingest queue. received =
            # what the listeners parsed; ingested = what reached the store;
            # dropped = what a full queue (or a store failure) refused and
            # COUNTED; lagging = the live backlog still waiting to be written.
            q = self._queue
            ingested = q.ingested if q is not None else 0
            dropped = q.dropped if q is not None else 0
            lagging = q.depth() if q is not None else 0
            capacity = q.limit if q is not None else INGEST_QUEUE_LIMIT

            return {
                "running": running,
                "bind": bind_val,
                "port": port_val,
                "protocol": "UDP + TCP",
                "protocols": ["udp", "tcp"],
                "exposed": any(x["bind"] == "0.0.0.0" for x in listeners),
                "receivedCount": sum(x["received"] for x in listeners),
                # storedCount stays the count of events written to the store
                # (deduped events are not re-counted), now produced by the worker.
                "storedCount": ingested,
                "ingestedCount": ingested,
                "droppedCount": dropped,
                "laggingCount": lagging,
                "queueCapacity": capacity,
                "queueUsed": lagging,
                "startedAt": started_at,
                "lastEventAt": last_event_at,
                "supportedPorts": list(DEFAULT_PORTS),
                "ports": sorted({x["port"] for x in listeners}),
                "listeners": listeners,
                "error": self._last_error,
            }


COLLECTOR = SyslogCollector()
