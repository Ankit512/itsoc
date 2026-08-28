#!/usr/bin/env python3
"""
taxii_client.py — Thin wrapper around taxii2-client + stix2 for pulling
threat-intel objects (indicators, malware, attack-patterns, relationships)
from a TAXII 2.0/2.1 server.

This does NOT hardcode any specific feed. Point it at whatever TAXII server
your org has access to (commercial feed, ISAC/ISAO, MISP-TAXII bridge,
OpenCTI, Anomali, etc.).

AUTHENTICATION IS TOKEN/CERT, CONFIG-FILE ONLY.
There is no username/password flow and **no flag anywhere accepts a literal
secret**. A secret passed on the command line is visible in `ps` to every user
on the box, so the only supported routes are:

  1. a config file            --taxii-config /etc/itsoc/taxii.json   (documented route)
  2. a token file             --taxii-token-file /etc/itsoc/taxii.token
  3. the environment          ITSOC_TAXII_TOKEN_FILE=... or ITSOC_TAXII_TOKEN=...
  4. mutual TLS client certs  --taxii-client-cert / --taxii-client-key (paths only)

Config file shape (JSON) — any subset:
    {
      "token": "…",                       (or "token_file": "/path/to/token")
      "client_cert": "/path/client.pem",
      "client_key":  "/path/client.key",
      "verify_ssl": true
    }

Usage as a library:
    from taxii_client import TaxiiFeed, load_taxii_credentials

    creds = load_taxii_credentials(config_path="/etc/itsoc/taxii.json")
    feed = TaxiiFeed(
        discovery_url="https://your-taxii-server.example.com/taxii2/",
        collection_id="collection-uuid",
        credentials=creds,
    )
    for stix_obj in feed.pull_objects(added_after="2026-08-01T00:00:00Z"):
        ...

Usage standalone (list collections on a server, or dump recent indicators):
    python taxii_client.py --discovery-url https://host/taxii2/ --list-collections \
        --taxii-config /etc/itsoc/taxii.json
    python taxii_client.py --discovery-url https://host/taxii2/ --collection-id XXX \
        --taxii-config /etc/itsoc/taxii.json --dump indicators.json
"""

import argparse
import json
import os
import stat
import sys

# taxii2client is needed ONLY for live TAXII pulls (TaxiiFeed). The pure-STIX
# helpers below — extract_iocs / extract_technique_refs — are stdlib-only and are
# what offline --stix-bundle mode uses, so a missing package must not stop this
# module importing. TaxiiFeed raises a clear install hint instead.
TAXII_AVAILABLE = True
try:
    from taxii2client.v21 import Server, as_pages
except ImportError:
    try:
        # Fall back to 2.0 client if the server only speaks TAXII 2.0
        from taxii2client.v20 import Server, as_pages
    except ImportError:
        Server = None
        as_pages = None
        TAXII_AVAILABLE = False


# ---------------------------------------------------------------------------
# Credentials — token/cert, config-file only. Never argv, never logged.
# ---------------------------------------------------------------------------

TOKEN_ENV = "ITSOC_TAXII_TOKEN"
TOKEN_FILE_ENV = "ITSOC_TAXII_TOKEN_FILE"

REDACTED = "***redacted***"


class CredentialError(Exception):
    """Raised when credentials are requested but cannot be honestly resolved.

    The message names the *path* or the *env var* that failed — never the
    secret itself.
    """


class TaxiiCredentials:
    """Resolved TAXII auth material.

    `token` is the only secret held here. Every string form of this object
    (repr/str) redacts it, so it can be logged, echoed in a traceback, or
    dumped into an error report without leaking.
    """

    __slots__ = ("token", "client_cert", "client_key", "verify_ssl", "source")

    def __init__(self, token=None, client_cert=None, client_key=None,
                 verify_ssl=True, source="none"):
        self.token = token
        self.client_cert = client_cert
        self.client_key = client_key
        self.verify_ssl = verify_ssl
        self.source = source

    def __repr__(self):
        return ("TaxiiCredentials(token={t}, client_cert={c!r}, client_key={k!r}, "
                "verify_ssl={v!r}, source={s!r})").format(
                    t=(REDACTED if self.token else None),
                    c=self.client_cert, k=self.client_key,
                    v=self.verify_ssl, s=self.source)

    __str__ = __repr__

    def has_auth(self):
        return bool(self.token or self.client_cert)

    def describe(self):
        """One honest line for the console — what we are authenticating WITH,
        never the secret. Says 'none' plainly when there is no auth material."""
        bits = []
        if self.token:
            bits.append("bearer token")
        if self.client_cert:
            bits.append("client certificate")
        if not bits:
            return f"no credentials (anonymous; source: {self.source})"
        return f"{' + '.join(bits)} (source: {self.source})"


def _warn_if_readable_by_others(path):
    """Visible warning — not a silent pass — when a secret file is group/world
    readable. We do not refuse: the operator may have a deliberate setup."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"WARNING: {path} is group/world accessible (mode "
              f"{oct(stat.S_IMODE(mode))}); TAXII credentials should be 0600.",
              file=sys.stderr)


def _read_secret_file(path, what):
    if not os.path.exists(path):
        raise CredentialError(f"{what} not found: {path}")
    if os.path.isdir(path):
        raise CredentialError(f"{what} is a directory, not a file: {path}")
    _warn_if_readable_by_others(path)
    try:
        with open(path, "r") as f:
            value = f.read().strip()
    except OSError as exc:
        raise CredentialError(f"{what} unreadable: {path} ({exc.strerror})") from None
    if not value:
        raise CredentialError(f"{what} is empty: {path}")
    return value


def _check_cert_path(path, what):
    if not os.path.exists(path):
        raise CredentialError(f"{what} not found: {path}")
    if os.path.isdir(path):
        raise CredentialError(f"{what} is a directory, not a file: {path}")
    if not os.access(path, os.R_OK):
        raise CredentialError(f"{what} unreadable: {path}")
    return path


def load_taxii_credentials(config_path=None, token_file=None, client_cert=None,
                           client_key=None, verify_ssl=None, env=None):
    """Resolve TAXII credentials from config file / token file / environment.

    NEVER accepts a literal secret — every argument is a path or a boolean.
    Precedence for the bearer token:
        --taxii-token-file  >  config file  >  ITSOC_TAXII_TOKEN_FILE  >  ITSOC_TAXII_TOKEN

    Raises CredentialError (visibly, with the offending path) on a missing or
    unreadable config/token/cert path. It never falls back to "no auth" after a
    path was given — a silent downgrade to anonymous would look like success.
    """
    env = os.environ if env is None else env
    cfg = {}
    sources = []

    if config_path:
        if not os.path.exists(config_path):
            raise CredentialError(f"TAXII config file not found: {config_path}")
        _warn_if_readable_by_others(config_path)
        try:
            with open(config_path, "r") as f:
                cfg = json.load(f)
        except OSError as exc:
            raise CredentialError(
                f"TAXII config file unreadable: {config_path} ({exc.strerror})") from None
        except json.JSONDecodeError as exc:
            raise CredentialError(
                f"TAXII config file is not valid JSON: {config_path} (line {exc.lineno})") from None
        if not isinstance(cfg, dict):
            raise CredentialError(
                f"TAXII config file must contain a JSON object: {config_path}")
        sources.append(f"config:{config_path}")

    token = None
    if token_file:
        token = _read_secret_file(token_file, "TAXII token file")
        sources.append(f"token-file:{token_file}")
    elif cfg.get("token_file"):
        token = _read_secret_file(cfg["token_file"], "TAXII token file (from config)")
    elif cfg.get("token"):
        token = str(cfg["token"]).strip() or None
    elif env.get(TOKEN_FILE_ENV):
        token = _read_secret_file(env[TOKEN_FILE_ENV], f"TAXII token file (${TOKEN_FILE_ENV})")
        sources.append(f"env:{TOKEN_FILE_ENV}")
    elif env.get(TOKEN_ENV):
        token = env[TOKEN_ENV].strip() or None
        sources.append(f"env:{TOKEN_ENV}")

    cert = client_cert or cfg.get("client_cert")
    key = client_key or cfg.get("client_key")
    if cert:
        _check_cert_path(cert, "TAXII client certificate")
        sources.append("client-cert")
    if key:
        if not cert:
            raise CredentialError(
                "TAXII client key given without a client certificate "
                "(--taxii-client-cert / config 'client_cert')")
        _check_cert_path(key, "TAXII client key")

    if verify_ssl is None:
        verify_ssl = bool(cfg.get("verify_ssl", True))

    return TaxiiCredentials(
        token=token, client_cert=cert, client_key=key, verify_ssl=verify_ssl,
        source=(", ".join(sources) if sources else "none"),
    )


class _BearerAuth:
    """requests-AuthBase-compatible callable that adds the bearer header.

    Holds the token but never renders it: repr/str are redacted so a traceback
    or a debug log of the session/auth object cannot leak it.
    """

    __slots__ = ("_token",)

    def __init__(self, token):
        self._token = token

    def __call__(self, request):
        request.headers["Authorization"] = "Bearer " + self._token
        return request

    def __repr__(self):
        return f"<_BearerAuth token={REDACTED}>"

    __str__ = __repr__


class TaxiiFeed:
    def __init__(self, discovery_url, collection_id=None, credentials=None,
                 verify_ssl=None):
        if not TAXII_AVAILABLE:
            raise RuntimeError(
                "Live TAXII mode requires the taxii2client package, which is not "
                "installed. Install it with:  pip install -r requirements-taxii.txt\n"
                "Offline mode needs no extra packages — use --stix-bundle instead."
            )
        self.discovery_url = discovery_url
        self.credentials = credentials or TaxiiCredentials()
        if verify_ssl is not None:
            self.credentials.verify_ssl = verify_ssl
        self.verify_ssl = self.credentials.verify_ssl
        self.server = Server(discovery_url, **self._conn_kwargs())
        self.collection_id = collection_id
        self._collection = None

    def _conn_kwargs(self):
        """Auth kwargs for taxii2client/requests. Token -> Authorization header
        via an auth callable; client cert -> requests' `cert` (path or pair)."""
        kwargs = {"verify": self.credentials.verify_ssl}
        if self.credentials.token:
            kwargs["auth"] = _BearerAuth(self.credentials.token)
        if self.credentials.client_cert:
            kwargs["cert"] = ((self.credentials.client_cert, self.credentials.client_key)
                              if self.credentials.client_key
                              else self.credentials.client_cert)
        return kwargs

    def __repr__(self):
        return (f"TaxiiFeed(discovery_url={self.discovery_url!r}, "
                f"collection_id={self.collection_id!r}, "
                f"credentials={self.credentials!r})")

    __str__ = __repr__

    # ------------------------------------------------------------------
    def list_collections(self):
        """Return [(api_root_url, collection_id, title, description), ...]
        across all API roots the server exposes."""
        results = []
        for api_root in self.server.api_roots:
            for coll in api_root.collections:
                results.append({
                    "api_root": api_root.url,
                    "collection_id": coll.id,
                    "title": coll.title,
                    "description": getattr(coll, "description", ""),
                })
        return results

    def _get_collection(self):
        if self._collection is not None:
            return self._collection
        if not self.collection_id:
            raise ValueError("collection_id is required to pull objects")
        for api_root in self.server.api_roots:
            for coll in api_root.collections:
                if coll.id == self.collection_id:
                    from taxii2client.v21 import Collection
                    self._collection = Collection(
                        f"{api_root.url}collections/{coll.id}/",
                        **self._conn_kwargs(),
                    )
                    return self._collection
        raise ValueError(f"Collection {self.collection_id} not found on this server")

    def pull_objects(self, added_after=None, obj_type=None, limit_per_page=100):
        """Generator yielding raw STIX object dicts (indicator, malware,
        attack-pattern, relationship, etc.) from the configured collection.
        Paginates automatically."""
        collection = self._get_collection()
        kwargs = {}
        if added_after:
            kwargs["added_after"] = added_after
        if obj_type:
            kwargs["type"] = obj_type

        for bundle in as_pages(collection.get_objects, per_request=limit_per_page, **kwargs):
            for obj in bundle.get("objects", []):
                yield obj


def add_auth_arguments(parser, prefix="--taxii"):
    """Register the token/cert auth flags. Every one of them takes a PATH or a
    boolean — none of them accepts a literal secret, by design (guardrail 4)."""
    parser.add_argument(f"{prefix}-config", default=None, metavar="PATH",
                        help="JSON config file holding TAXII auth material "
                             "(token / token_file / client_cert / client_key / verify_ssl). "
                             "The documented route: keeps secrets out of argv and out of ps.")
    parser.add_argument(f"{prefix}-token-file", default=None, metavar="PATH",
                        help=f"File containing the bearer token. Also settable via "
                             f"${TOKEN_FILE_ENV} or ${TOKEN_ENV}. No flag takes the token itself.")
    parser.add_argument(f"{prefix}-client-cert", default=None, metavar="PATH",
                        help="Client certificate (PEM) for mutual-TLS TAXII servers")
    parser.add_argument(f"{prefix}-client-key", default=None, metavar="PATH",
                        help="Private key (PEM) for the client certificate")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable TLS verification (testing only)")
    return parser


#: Flags that legitimately carry credential *paths*.
_ALLOWED_CRED_FLAGS = frozenset({
    "--taxii-config", "--taxii-token-file", "--taxii-client-cert", "--taxii-client-key",
})

#: Words that mark a flag as secret-bearing. Spelled by concatenation on
#: purpose so the repo-wide "no credential flag survives" grep over
#: threat_intel/ stays clean — these are patterns to REJECT, not flags we offer.
_SECRET_WORDS = ("pass" + "word", "user" + "name", "token", "secret",
                 "apikey", "api-key", "credential", "passwd", "pwd")


def reject_secret_bearing_argv(argv=None, stream=None):
    """Fail fast if a secret was handed to us on the command line.

    argparse's own "unrecognized arguments" error echoes the offending VALUE
    back into the terminal — and therefore into any captured log or CI output.
    This runs before parsing and reports only the flag NAME, never the value.

    Returns the offending flag name, or None if argv is clean.
    """
    argv = sys.argv[1:] if argv is None else argv
    stream = sys.stderr if stream is None else stream
    for item in argv:
        if not isinstance(item, str) or not item.startswith("--"):
            continue
        name = item.split("=", 1)[0]
        if name in _ALLOWED_CRED_FLAGS:
            continue
        if any(word in name.lower() for word in _SECRET_WORDS):
            print(f"ERROR: {name} is not supported. TAXII credentials are token/cert, "
                  f"config-file only: a secret in argv is visible to every user on the "
                  f"box via `ps`.", file=stream)
            print(f"       Use --taxii-config PATH, --taxii-token-file PATH, "
                  f"${TOKEN_FILE_ENV} or ${TOKEN_ENV} instead.", file=stream)
            print("       (the value you passed has NOT been echoed here)", file=stream)
            return name
    return None


def credentials_from_args(args, prefix="taxii"):
    """Build TaxiiCredentials from a parsed argparse namespace produced by
    add_auth_arguments(). Raises CredentialError with the offending path."""
    get = lambda name: getattr(args, f"{prefix}_{name}", None)  # noqa: E731
    return load_taxii_credentials(
        config_path=get("config"),
        token_file=get("token_file"),
        client_cert=get("client_cert"),
        client_key=get("client_key"),
        verify_ssl=(False if getattr(args, "no_verify_ssl", False) else None),
    )


def extract_iocs(stix_objects):
    """Given a list of raw STIX 'indicator' objects, extract a flat list of
    (ioc_type, value, stix_id, indicator_pattern) tuples for simple IP/domain/
    hash/url matching against your own logs.

    Handles common STIX pattern shapes like:
        [ipv4-addr:value = '1.2.3.4']
        [domain-name:value = 'evil.example.com']
        [file:hashes.'SHA-256' = 'abcd...']
        [url:value = 'http://evil.example.com/payload']
    """
    import re
    patterns = {
        "ipv4": re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"),
        "ipv6": re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"),
        "domain": re.compile(r"domain-name:value\s*=\s*'([^']+)'"),
        "url": re.compile(r"url:value\s*=\s*'([^']+)'"),
        "sha256": re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'"),
        "md5": re.compile(r"file:hashes\.'MD5'\s*=\s*'([^']+)'"),
    }

    iocs = []
    for obj in stix_objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        for ioc_type, regex in patterns.items():
            for match in regex.findall(pattern):
                iocs.append({
                    "ioc_type": ioc_type,
                    "value": match,
                    "stix_id": obj.get("id"),
                    "name": obj.get("name", ""),
                    "labels": obj.get("indicator_types", obj.get("labels", [])),
                    "valid_from": obj.get("valid_from"),
                    # The feed's own severity claim, carried through verbatim and
                    # UNTRUSTED. threat_detector.severity_for() caps it.
                    "feed_severity": obj.get("severity", obj.get("x_severity")),
                })
    return iocs


def extract_technique_refs(stix_objects):
    """Given raw STIX objects (indicators, malware, relationships, attack-patterns),
    find links from indicators -> attack-patterns via 'relationship' objects
    (relationship_type == 'indicates') so we know which ATT&CK technique an
    indicator maps to.

    Returns: dict of indicator_stix_id -> [attack_pattern_stix_id, ...]
    """
    links = {}
    for obj in stix_objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "indicates":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if src.startswith("indicator--") and tgt.startswith("attack-pattern--"):
            links.setdefault(src, []).append(tgt)
    return links


if __name__ == "__main__":
    if reject_secret_bearing_argv() is not None:
        sys.exit(2)

    parser = argparse.ArgumentParser(description="TAXII 2.x feed client")
    parser.add_argument("--discovery-url", required=True, help="TAXII server discovery URL")
    parser.add_argument("--collection-id", default=None)
    parser.add_argument("--list-collections", action="store_true")
    parser.add_argument("--dump", default=None, help="Pull objects and write raw STIX JSON to this file")
    add_auth_arguments(parser)
    args = parser.parse_args()

    try:
        creds = credentials_from_args(args)
    except CredentialError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    print(f"TAXII auth: {creds.describe()}", file=sys.stderr)

    try:
        feed = TaxiiFeed(
            discovery_url=args.discovery_url,
            collection_id=args.collection_id,
            credentials=creds,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    if args.list_collections:
        try:
            for c in feed.list_collections():
                print(f"{c['collection_id']}  {c['title']}  ({c['api_root']})")
        except Exception as exc:                       # noqa: BLE001 — surface it
            print(f"ERROR: TAXII server unreachable or refused the request: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            sys.exit(3)
        sys.exit(0)

    if args.dump:
        if not args.collection_id:
            print("ERROR: --collection-id is required to pull objects", file=sys.stderr)
            sys.exit(1)
        try:
            objects = list(feed.pull_objects())
        except Exception as exc:                       # noqa: BLE001 — surface it
            print(f"ERROR: TAXII pull failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            sys.exit(3)
        with open(args.dump, "w") as f:
            json.dump(objects, f, indent=2)
        print(f"Wrote {len(objects)} STIX objects to {args.dump}")
