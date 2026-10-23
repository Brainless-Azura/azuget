#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AzuGet v1 - un seul outil pour tout le flux de mises à jour signées.

  keygen        crée la paire de clés Ed25519 (sur le PC de publication)
  init-feed     prépare le dossier docs/v1 du dépôt de flux
  publish       publie une version : téléversement, manifestes signés, git push, réveil des miroirs
  sign / verify signe ou vérifie des fichiers JSON du flux
  check         fait ce que fera un lanceur : y a-t-il une mise à jour ? (implémentation de référence)
  mirror        côté Raspberry Pi : synchronise le miroir depuis le dépôt de flux
  status        résume l'état des miroirs
  github-setup  crée le dépôt GitHub + GitHub Pages à partir du dépôt local (gh doit être connecté)
  selftest      autotests (signatures, versions)

Dépendance : cryptography (pip install cryptography ; sur Debian : apt install python3-cryptography).
Python 3.9 ou plus récent. Le même fichier sert sur le PC (publication) et sur les Pi (miroir).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

AZUGET_FORMAT = 1
TOOL_VERSION = "1.0.0"
USER_AGENT = "azuget/" + TOOL_VERSION
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$")
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_FEED_SUBDIR = "docs"
EXIT_OK = 0
EXIT_UPDATE_AVAILABLE = 10
EXIT_ERROR = 2
EXIT_BAD_SIGNATURE = 3


class AzuGetError(Exception):
    """Erreur attendue : message en clair, pas de trace Python."""


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S") + " " + msg, flush=True)


def die(msg: str, code: int = EXIT_ERROR) -> "NoReturn":  # type: ignore[name-defined]
    print("azuget : " + msg, file=sys.stderr, flush=True)
    sys.exit(code)


def canonical_json(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_json_bytes(data: bytes):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AzuGetError("JSON invalide : %s" % exc)


def write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-%d" % os.getpid())
    with open(tmp, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


def sha256_file(path: Path):
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def human_size(n: int) -> str:
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return ("%d %s" % (n, unit)) if unit == "o" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%d o" % n


def version_key(v: str):
    """Clé de tri : 1.2 == 1.2.0 ; 1.0.0-beta < 1.0.0 ; les parties non numériques se comparent en texte."""
    v = v.strip()
    if v[:1] in ("v", "V"):
        v = v[1:]
    v = v.split("+", 1)[0]
    main, _, pre = v.partition("-")
    parts = []
    for part in main.split("."):
        m = re.match(r"(\d*)(.*)", part)
        num = int(m.group(1)) if m.group(1) else 0
        parts.append((num, m.group(2)))
    while len(parts) < 4:
        parts.append((0, ""))
    if pre:
        pre_key = (0, tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")))
    else:
        pre_key = (1, ())
    return (tuple(parts), pre_key)


def version_cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def which(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise AzuGetError("programme introuvable dans le PATH : %s" % name)
    return path


def run(cmd, cwd=None, check=True, capture=False, env=None, input_bytes=None, timeout=None):
    kwargs = dict(cwd=str(cwd) if cwd else None, env=env, timeout=timeout)
    if capture:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if input_bytes is not None:
        kwargs.update(input=input_bytes)
    proc = subprocess.run([str(c) for c in cmd], **kwargs)
    if check and proc.returncode != 0:
        detail = ""
        if capture:
            detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise AzuGetError("la commande a échoué (%d) : %s%s" % (proc.returncode, " ".join(str(c) for c in cmd), ("\n" + detail) if detail else ""))
    return proc


def git(args, cwd, capture=True, check=True):
    env = dict(os.environ)
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    return run([which("git")] + list(args), cwd=cwd, capture=capture, check=check, env=env)


# ---------------------------------------------------------------------------
# Cryptographie : Ed25519 via cryptography
# ---------------------------------------------------------------------------

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        raise AzuGetError("le module Python 'cryptography' manque : pip install cryptography (Windows) ou apt install python3-cryptography (Debian)")
    return ed25519, serialization, InvalidSignature


def key_id_of(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def _read_hex_key_file(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AzuGetError("clé illisible : %s (%s)" % (path, exc))
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if HEX64_RE.match(line.lower()):
            return bytes.fromhex(line)
        raise AzuGetError("format de clé inattendu dans %s" % path)
    raise AzuGetError("aucune clé dans %s" % path)


def load_private_key(path: Path):
    ed25519, _, _ = _crypto()
    seed = _read_hex_key_file(path)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return priv


def public_raw(priv) -> bytes:
    _, serialization, _ = _crypto()
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_pubkeys(values) -> dict:
    """values : liste d'hexadécimaux (64 car.) ou de chemins de fichiers .pub -> {key_id: bytes}."""
    keys = {}
    for v in values or []:
        v = str(v).strip()
        if HEX64_RE.match(v.lower()):
            raw = bytes.fromhex(v)
        else:
            raw = _read_hex_key_file(Path(v))
        keys[key_id_of(raw)] = raw
    if not keys:
        raise AzuGetError("aucune clé publique de confiance (option --pubkey, fichier keys/azuget-signing.pub ou config)")
    return keys


def sign_bytes(priv, data: bytes) -> dict:
    pub = public_raw(priv)
    return {"azuget_sig": 1, "alg": "ed25519", "key_id": key_id_of(pub), "sig": priv.sign(data).hex()}


def verify_bytes(pubkeys: dict, data: bytes, sig_obj) -> tuple:
    """-> (ok, key_id, raison)."""
    ed25519, _, InvalidSignature = _crypto()
    if not isinstance(sig_obj, dict) or sig_obj.get("azuget_sig") != 1 or sig_obj.get("alg") != "ed25519":
        return False, None, "fichier .sig inattendu"
    kid = sig_obj.get("key_id")
    raw = pubkeys.get(kid)
    if raw is None:
        return False, kid, "clé inconnue (key_id %s)" % kid
    try:
        sig = bytes.fromhex(sig_obj.get("sig", ""))
        ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(sig, data)
    except (ValueError, InvalidSignature):
        return False, kid, "signature invalide"
    return True, kid, "ok"


def sign_file(priv, path: Path) -> Path:
    data = path.read_bytes()
    sig_path = path.with_name(path.name + ".sig")
    write_atomic(sig_path, canonical_json(sign_bytes(priv, data)))
    return sig_path


def verify_file(pubkeys: dict, path: Path) -> tuple:
    sig_path = path.with_name(path.name + ".sig")
    if not sig_path.exists():
        return False, None, "fichier .sig absent"
    try:
        sig_obj = read_json_bytes(sig_path.read_bytes())
    except AzuGetError as exc:
        return False, None, str(exc)
    return verify_bytes(pubkeys, path.read_bytes(), sig_obj)


def write_json_signed(priv, path: Path, obj) -> None:
    write_atomic(path, canonical_json(obj))
    sign_file(priv, path)


# ---------------------------------------------------------------------------
# HTTP (urllib, sans dépendance)
# ---------------------------------------------------------------------------

def http_open(url: str, timeout: float = 30, method: str = "GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    return urllib.request.urlopen(req, timeout=timeout)


def http_get(url: str, timeout: float = 30, max_bytes: int = 8 * 1024 * 1024, retries: int = 3) -> bytes:
    last = None
    for attempt in range(retries):
        try:
            with http_open(url, timeout=timeout) as resp:
                data = resp.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise AzuGetError("réponse trop grande : %s" % url)
                return data
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410, 403):
                raise AzuGetError("HTTP %d : %s" % (exc.code, url))
            last = exc
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            last = exc
        time.sleep(1.5 * (attempt + 1))
    raise AzuGetError("injoignable : %s (%s)" % (url, last))


def http_head_size(url: str, timeout: float = 30):
    """-> (code, taille ou None) en suivant les redirections."""
    try:
        with http_open(url, timeout=timeout, method="HEAD") as resp:
            length = resp.headers.get("Content-Length")
            return resp.status, (int(length) if length is not None else None)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def http_download(url: str, dest: Path, expected_sha256: str, expected_size: int, timeout: float = 60) -> None:
    """Télécharge vers dest.part en vérifiant taille et SHA-256, puis renomme. Lève AzuGetError sinon."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    h = hashlib.sha256()
    got = 0
    try:
        with http_open(url, timeout=timeout) as resp, open(part, "wb") as fh:
            length = resp.headers.get("Content-Length")
            if length is not None and int(length) != expected_size:
                raise AzuGetError("taille annoncée %s au lieu de %d : %s" % (length, expected_size, url))
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                got += len(chunk)
                if got > expected_size:
                    raise AzuGetError("plus d'octets qu'annoncé : %s" % url)
                h.update(chunk)
                fh.write(chunk)
        if got != expected_size:
            raise AzuGetError("taille reçue %d au lieu de %d : %s" % (got, expected_size, url))
        if h.hexdigest() != expected_sha256:
            raise AzuGetError("SHA-256 différent de celui du manifeste : %s" % url)
        os.replace(part, dest)
    except urllib.error.HTTPError as exc:
        raise AzuGetError("HTTP %d : %s" % (exc.code, url))
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        raise AzuGetError("téléchargement interrompu : %s (%s)" % (url, exc))
    finally:
        if part.exists():
            try:
                part.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Configuration du PC de publication (~/.azuget/config.json)
# ---------------------------------------------------------------------------

def config_path() -> Path:
    env = os.environ.get("AZUGET_CONFIG")
    return Path(env) if env else Path.home() / ".azuget" / "config.json"


def load_config(required: bool = False) -> dict:
    p = config_path()
    if not p.exists():
        if required:
            raise AzuGetError("configuration absente : %s (voir README, section « PC de publication »)" % p)
        return {}
    return read_json_bytes(p.read_bytes())


def save_config(cfg: dict) -> None:
    write_atomic(config_path(), canonical_json(cfg), mode=0o600)


def feed_v1_dir(cfg: dict, override=None) -> Path:
    base = Path(override) if override else Path(cfg.get("feed_dir") or ".")
    return base / cfg.get("feed_subdir", DEFAULT_FEED_SUBDIR) / "v1"


def default_pubkey_sources(cfg: dict):
    out = []
    if cfg.get("pubkeys"):
        out.extend(cfg["pubkeys"])
    if cfg.get("feed_dir"):
        p = Path(cfg["feed_dir"]) / "keys" / "azuget-signing.pub"
        if p.exists():
            out.append(str(p))
    if cfg.get("key_file") and Path(cfg["key_file"]).exists():
        try:
            out.append(public_raw(load_private_key(Path(cfg["key_file"]))).hex())
        except AzuGetError:
            pass
    return out


# ---------------------------------------------------------------------------
# Manifestes
# ---------------------------------------------------------------------------

def validate_manifest(m, expected_project=None) -> None:
    if not isinstance(m, dict) or m.get("azuget") != AZUGET_FORMAT:
        raise AzuGetError("manifeste : format azuget %r non pris en charge" % (m.get("azuget") if isinstance(m, dict) else None))
    for field in ("project", "version", "published", "assets", "channel"):
        if field not in m:
            raise AzuGetError("manifeste : champ manquant « %s »" % field)
    if not PROJECT_RE.match(m["project"]):
        raise AzuGetError("manifeste : identifiant de projet invalide")
    if expected_project and m["project"] != expected_project:
        raise AzuGetError("manifeste : projet « %s » au lieu de « %s »" % (m["project"], expected_project))
    if not VERSION_RE.match(m["version"]):
        raise AzuGetError("manifeste : version invalide « %s »" % m["version"])
    parse_iso(m["published"])
    if not isinstance(m["assets"], list):
        raise AzuGetError("manifeste : assets doit être une liste")
    for a in m["assets"]:
        for field in ("name", "size", "sha256", "urls"):
            if field not in a:
                raise AzuGetError("manifeste : asset sans « %s »" % field)
        if not ASSET_NAME_RE.match(a["name"]):
            raise AzuGetError("manifeste : nom de fichier invalide « %s »" % a["name"])
        if not HEX64_RE.match(str(a["sha256"]).lower()):
            raise AzuGetError("manifeste : SHA-256 invalide pour %s" % a["name"])
        if not isinstance(a["size"], int) or a["size"] < 0:
            raise AzuGetError("manifeste : taille invalide pour %s" % a["name"])


def asset_candidate_urls(feed_base: str, m: dict, a: dict):
    """URL du miroir (relative au flux) d'abord, puis les URL absolues du manifeste."""
    urls = []
    if feed_base:
        urls.append("%s/v1/%s/files/%s/%s" % (feed_base.rstrip("/"), m["project"], m["version"], a["name"]))
    for u in a.get("urls", []):
        if u not in urls:
            urls.append(u)
    return urls


# ---------------------------------------------------------------------------
# keygen / sign / verify / init-feed
# ---------------------------------------------------------------------------

def restrict_file_to_owner(path: Path) -> None:
    if os.name == "nt":
        user = os.environ.get("USERNAME")
        if user:
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", "%s:F" % user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.chmod(path, 0o600)


def cmd_keygen(args) -> int:
    ed25519, _, _ = _crypto()
    out = Path(args.dir) if args.dir else Path.home() / ".azuget" / "keys"
    out.mkdir(parents=True, exist_ok=True)
    key_path = out / "azuget-signing.key"
    pub_path = out / "azuget-signing.pub"
    if key_path.exists() and not args.force:
        raise AzuGetError("%s existe déjà (utilise --force pour la remplacer, en sachant que les lanceurs qui font confiance à l'ancienne clé ne reconnaîtront plus les nouvelles publications)" % key_path)
    priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = public_raw(priv)
    kid = key_id_of(pub)
    key_text = ("# AzuGet - clé privée Ed25519 (graine en hexadécimal). NE LA PARTAGE JAMAIS.\n"
                "# Sauvegarde ce fichier dans un gestionnaire de mots de passe : perdue, plus aucune mise à jour\n"
                "# ne pourra être signée pour les lanceurs qui font confiance à cette clé.\n"
                "# key_id: %s\n# pubkey: %s\n%s\n" % (kid, pub.hex(), seed.hex()))
    write_atomic(key_path, key_text.encode("utf-8"), mode=0o600)
    restrict_file_to_owner(key_path)
    write_atomic(pub_path, ("# AzuGet - clé publique Ed25519 (hexadécimal), key_id %s\n%s\n" % (kid, pub.hex())).encode("utf-8"))
    print("clé privée  : %s" % key_path)
    print("clé publique: %s" % pub_path)
    print("key_id      : %s" % kid)
    print("pubkey      : %s" % pub.hex())
    return EXIT_OK


def cmd_sign(args) -> int:
    cfg = load_config()
    key_file = Path(args.key or cfg.get("key_file") or "")
    if not key_file or not key_file.exists():
        raise AzuGetError("clé privée introuvable (option --key ou key_file dans la config)")
    priv = load_private_key(key_file)
    for f in args.files:
        p = Path(f)
        read_json_bytes(p.read_bytes())
        print("signé : %s" % sign_file(priv, p))
    return EXIT_OK


def iter_feed_json(v1dir: Path):
    for p in sorted(v1dir.rglob("*.json")):
        if "files" in p.relative_to(v1dir).parts:
            continue
        yield p


def cmd_verify(args) -> int:
    cfg = load_config()
    pubkeys = load_pubkeys(args.pubkey or default_pubkey_sources(cfg))
    files = [Path(f) for f in args.files]
    if args.feed_dir or not files:
        v1 = feed_v1_dir(cfg, args.feed_dir)
        if not v1.exists():
            raise AzuGetError("dossier de flux introuvable : %s" % v1)
        files = list(iter_feed_json(v1))
    bad = 0
    for p in files:
        ok, kid, why = verify_file(pubkeys, p)
        print("%-8s %s  (%s)" % ("OK" if ok else "ERREUR", p, why if not ok else "clé %s" % kid))
        if not ok:
            bad += 1
        elif p.name == "latest.json" or p.parent.name == "releases":
            try:
                validate_manifest(read_json_bytes(p.read_bytes()))
            except AzuGetError as exc:
                print("ERREUR   %s  (%s)" % (p, exc))
                bad += 1
    print("%d fichier(s), %d en erreur" % (len(files), bad))
    return EXIT_OK if bad == 0 else EXIT_BAD_SIGNATURE


def ensure_keys_json(priv, v1: Path) -> None:
    pub = public_raw(priv)
    kid = key_id_of(pub)
    path = v1 / "keys.json"
    keys = {"azuget": AZUGET_FORMAT, "generated": now_iso(), "keys": []}
    if path.exists():
        try:
            keys = read_json_bytes(path.read_bytes())
        except AzuGetError:
            pass
    if not any(k.get("key_id") == kid for k in keys.get("keys", [])):
        keys.setdefault("keys", []).append({"key_id": kid, "pubkey": pub.hex(), "status": "active", "since": now_iso()})
        keys["generated"] = now_iso()
        write_json_signed(priv, path, keys)


def load_index(v1: Path) -> dict:
    path = v1 / "index.json"
    if path.exists():
        return read_json_bytes(path.read_bytes())
    return {"azuget": AZUGET_FORMAT, "generated": now_iso(), "projects": []}


def cmd_init_feed(args) -> int:
    cfg = load_config()
    key_file = Path(args.key or cfg.get("key_file") or "")
    if not key_file.exists():
        raise AzuGetError("clé privée introuvable (option --key ou key_file dans la config) ; lance d'abord azuget keygen")
    priv = load_private_key(key_file)
    v1 = feed_v1_dir(cfg, args.feed_dir)
    v1.mkdir(parents=True, exist_ok=True)
    (v1.parent / ".nojekyll").write_bytes(b"")
    if not (v1 / "index.json").exists():
        write_json_signed(priv, v1 / "index.json", load_index(v1))
    ensure_keys_json(priv, v1)
    print("flux initialisé : %s" % v1)
    return EXIT_OK


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------

class Asset:
    def __init__(self, path: Path, platform: str, kind: str):
        self.path = path
        self.name = path.name
        self.platform = platform or "any"
        self.kind = kind or "full"
        self.sha256, self.size = sha256_file(path)


def parse_asset_spec(spec: str) -> Asset:
    parts = spec.split("|")
    path = Path(parts[0]).expanduser()
    if not path.is_file():
        raise AzuGetError("fichier introuvable : %s" % path)
    if not ASSET_NAME_RE.match(path.name):
        raise AzuGetError("nom de fichier non autorisé (lettres, chiffres, . _ + -) : %s" % path.name)
    platform = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "any"
    kind = parts[2].strip() if len(parts) > 2 and parts[2].strip() else "full"
    return Asset(path, platform, kind)


def ssh_command(cfg: dict):
    exe = cfg.get("ssh_exe") or "ssh"
    opts = cfg.get("ssh_opts")
    if opts is None:
        opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    return [exe] + list(opts)


def upload_to_hub(cfg: dict, project: str, version: str, assets) -> None:
    hub = cfg.get("hub") or {}
    if not hub.get("ssh"):
        raise AzuGetError("config : hub.ssh manquant (ex. omnipi@omnipi-pi4.local)")
    inbox = hub.get("inbox", "/srv/azuget-inbox")
    remote_dir = "%s/%s/%s" % (inbox, project, version)
    remote_cmd = ("umask 002 && mkdir -p '%s' && chmod 2775 '%s/%s' '%s' 2>/dev/null; tar -x -C '%s'"
                  % (remote_dir, inbox, project, remote_dir, remote_dir))
    cmd = ssh_command(cfg) + [hub["ssh"], remote_cmd]
    log("téléversement vers %s:%s (%s)" % (hub["ssh"], remote_dir, ", ".join(human_size(a.size) for a in assets)))
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdin, mode="w|") as tf:
            for a in assets:
                info = tf.gettarinfo(str(a.path), arcname=a.name)
                info.mode = 0o664
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(a.path, "rb") as fh:
                    tf.addfile(info, fh)
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
    rc = proc.wait(timeout=6 * 3600)
    if rc != 0:
        raise AzuGetError("le téléversement SSH a échoué (code %d)" % rc)


def github_release_upload(cfg: dict, repo: str, tag: str, title: str, notes: str, assets) -> None:
    gh = which("gh")
    view = run([gh, "release", "view", tag, "--repo", repo, "--json", "tagName"], capture=True, check=False)
    files = [str(a.path) for a in assets]
    if view.returncode != 0:
        log("création de la release GitHub %s dans %s" % (tag, repo))
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as fh:
            fh.write(notes or title)
            notes_file = fh.name
        try:
            run([gh, "release", "create", tag, "--repo", repo, "--title", title, "--notes-file", notes_file, "--target", cfg.get("github_branch", "main")] + files, capture=True)
        finally:
            os.unlink(notes_file)
    else:
        log("release %s existante : ajout des fichiers" % tag)
        run([gh, "release", "upload", tag, "--repo", repo, "--clobber"] + files, capture=True)


def check_urls_online(assets_urls) -> None:
    for name, size, url in assets_urls:
        for attempt in range(6):
            code, length = http_head_size(url)
            if code == 200 and (length is None or length == size):
                break
            time.sleep(3)
        else:
            raise AzuGetError("fichier publié mais injoignable ou de mauvaise taille : %s (HTTP %s, %s)" % (url, code, length))


def cmd_publish(args) -> int:
    cfg = load_config(required=True)
    if not PROJECT_RE.match(args.project):
        raise AzuGetError("identifiant de projet invalide (minuscules, chiffres, tirets) : %s" % args.project)
    if not VERSION_RE.match(args.version):
        raise AzuGetError("version invalide (ex. 1.2.3 ou 1.2.3-beta.1) : %s" % args.version)
    key_file = Path(args.key or cfg.get("key_file") or "")
    if not key_file.exists():
        raise AzuGetError("clé privée introuvable : %s" % key_file)
    priv = load_private_key(key_file)
    v1 = feed_v1_dir(cfg, args.feed_dir)
    feed_root = v1.parent.parent
    if not (feed_root / ".git").exists():
        raise AzuGetError("%s n'est pas un dépôt git (feed_dir de la config)" % feed_root)
    pdir = v1 / args.project
    assets = [parse_asset_spec(s) for s in args.asset]
    if not assets:
        raise AzuGetError("au moins un --asset est nécessaire")
    names = [a.name for a in assets]
    if len(set(names)) != len(names):
        raise AzuGetError("deux fichiers portent le même nom")

    hosts = [h.strip() for h in (args.host or ",".join(cfg.get("default_hosts", ["pi"]))).split(",") if h.strip()]
    for h in hosts:
        if h not in ("pi", "github"):
            raise AzuGetError("hôte inconnu : %s (pi ou github)" % h)
    repo = args.repo or cfg.get("github_repo")
    if "github" in hosts and not repo:
        raise AzuGetError("hôte github : précise --repo owner/nom ou github_repo dans la config")
    tag = args.tag
    if "github" in hosts and not tag:
        tag = ("%s-v%s" % (args.project, args.version)) if repo == cfg.get("github_repo") else ("v%s" % args.version)

    # Manifeste précédent et historique
    latest_path = pdir / "latest.json"
    previous = read_json_bytes(latest_path.read_bytes()) if latest_path.exists() else None
    release_path = pdir / "releases" / ("%s.json" % args.version)
    if release_path.exists() and not args.force:
        raise AzuGetError("la version %s existe déjà dans le flux (--force pour la réécrire)" % args.version)
    if previous and version_cmp(args.version, previous["version"]) <= 0 and not args.force_latest:
        raise AzuGetError("la version %s n'est pas plus récente que la dernière publiée (%s) ; --force-latest pour l'imposer quand même"
                          % (args.version, previous["version"]))

    name = args.name or (previous or {}).get("name") or args.project
    notes = args.notes or ""
    if args.notes_file:
        notes = Path(args.notes_file).read_text(encoding="utf-8")
    channel = args.channel or (previous or {}).get("channel") or "stable"

    hub_url = (cfg.get("hub") or {}).get("url", "").rstrip("/")
    manifest_assets = []
    online_checks = []
    for a in assets:
        urls = []
        for h in hosts:
            if h == "github":
                u = "https://github.com/%s/releases/download/%s/%s" % (repo, tag, a.name)
                urls.append(u)
                online_checks.append((a.name, a.size, u))
            elif h == "pi":
                if not hub_url:
                    raise AzuGetError("config : hub.url manquant (ex. http://omnipi-pi4.local)")
                urls.append("%s/v1/%s/files/%s/%s" % (hub_url, args.project, args.version, a.name))
        manifest_assets.append({"name": a.name, "platform": a.platform, "kind": a.kind, "size": a.size, "sha256": a.sha256, "urls": urls})

    manifest = {
        "azuget": AZUGET_FORMAT,
        "project": args.project,
        "name": name,
        "channel": channel,
        "version": args.version,
        "published": now_iso(),
        "notes": notes,
        "notes_url": args.notes_url or (previous or {}).get("notes_url"),
        "min_launcher": args.min_launcher,
        "assets": manifest_assets,
    }
    validate_manifest(manifest, args.project)
    if args.dry_run:
        print(canonical_json(manifest).decode("utf-8"))
        print("(simulation : rien n'a été téléversé ni écrit)")
        return EXIT_OK

    # 1. téléversements
    if "pi" in hosts:
        upload_to_hub(cfg, args.project, args.version, assets)
    if "github" in hosts:
        github_release_upload(cfg, repo, tag, "%s %s" % (name, args.version), notes, assets)
        check_urls_online(online_checks)

    # 2. manifestes signés
    write_json_signed(priv, release_path, manifest)
    if previous is None or version_cmp(args.version, previous["version"]) > 0 or args.force_latest:
        write_json_signed(priv, latest_path, manifest)
    versions_path = pdir / "versions.json"
    versions = read_json_bytes(versions_path.read_bytes()) if versions_path.exists() else {"azuget": AZUGET_FORMAT, "project": args.project, "versions": []}
    versions["versions"] = [v for v in versions["versions"] if v.get("version") != args.version]
    versions["versions"].append({"version": args.version, "channel": channel, "published": manifest["published"], "manifest": "releases/%s.json" % args.version})
    versions["versions"].sort(key=lambda v: version_key(v["version"]), reverse=True)
    versions["generated"] = now_iso()
    write_json_signed(priv, versions_path, versions)
    index = load_index(v1)
    current_latest = read_json_bytes(latest_path.read_bytes())
    entry = {"id": args.project, "name": current_latest["name"], "channel": current_latest["channel"], "version": current_latest["version"],
             "published": current_latest["published"], "manifest": "%s/latest.json" % args.project}
    index["projects"] = [p for p in index.get("projects", []) if p.get("id") != args.project] + [entry]
    index["projects"].sort(key=lambda p: p["id"])
    index["generated"] = now_iso()
    write_json_signed(priv, v1 / "index.json", index)
    ensure_keys_json(priv, v1)
    log("manifestes écrits dans %s" % pdir)

    # 3. git
    rel = str(v1.relative_to(feed_root)).replace("\\", "/")
    git(["add", "-A", "--", rel], cwd=feed_root)
    status = git(["status", "--porcelain", "--", rel], cwd=feed_root).stdout.decode("utf-8", "replace").strip()
    if status:
        git(["commit", "-q", "-m", "azuget: %s %s" % (args.project, args.version)], cwd=feed_root)
        log("commit : azuget: %s %s" % (args.project, args.version))
    if not args.no_push:
        branch = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=feed_root).stdout.decode().strip()
        remotes = [r for r in git(["remote"], cwd=feed_root).stdout.decode().split() if r]
        if not remotes:
            log("attention : aucun dépôt distant configuré, rien n'a été poussé")
        for r in remotes:
            proc = git(["push", "-q", r, "HEAD:%s" % branch], cwd=feed_root, check=False)
            if proc.returncode == 0:
                log("poussé vers %s" % r)
            else:
                log("ECHEC push vers %s : %s" % (r, proc.stderr.decode("utf-8", "replace").strip()))

    # 4. réveil des miroirs (après que le hub sert la version, sinon ils la chercheraient trop tôt)
    if not args.no_kick:
        if "pi" in hosts and hub_url and not args.no_push:
            deadline = time.time() + 90
            while time.time() < deadline:
                try:
                    m = read_json_bytes(http_get("%s/v1/%s/latest.json" % (hub_url, args.project), timeout=10, retries=1))
                    if m.get("version") == args.version:
                        log("hub %s : version servie" % hub_url)
                        break
                except AzuGetError:
                    pass
                time.sleep(3)
            else:
                log("hub %s : la version n'est pas encore servie (synchronisation en retard ?)" % hub_url)
        for target in cfg.get("kick", []):
            proc = subprocess.run(ssh_command(cfg) + [target, "sudo -n systemctl start azuget-sync.service"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
            log("miroir %s : %s" % (target, "synchronisation lancée" if proc.returncode == 0 else "pas réveillé (%s)" % proc.stderr.decode("utf-8", "replace").strip()[:120]))

    # 5. attente optionnelle
    if args.wait:
        deadline = time.time() + args.wait
        pending = {u.rstrip("/") for u in cfg.get("feed_urls", [])}
        while pending and time.time() < deadline:
            for base in sorted(pending):
                try:
                    m = read_json_bytes(http_get("%s/v1/%s/latest.json" % (base, args.project), timeout=10, retries=1))
                    if m.get("version") == args.version:
                        log("visible sur %s" % base)
                        pending.discard(base)
                except AzuGetError:
                    pass
            if pending:
                time.sleep(5)
        for base in sorted(pending):
            log("pas encore visible sur %s" % base)
    print("publié : %s %s" % (args.project, args.version))
    for a in manifest_assets:
        for u in a["urls"]:
            print("  %s" % u)
    return EXIT_OK


# ---------------------------------------------------------------------------
# check : implémentation de référence d'un lanceur
# ---------------------------------------------------------------------------

def fetch_manifest(feed_base: str, project: str, pubkeys: dict, path: str = "latest.json"):
    base = feed_base.rstrip("/")
    url = "%s/v1/%s/%s" % (base, project, path)
    data = http_get(url, timeout=20, retries=2)
    sig = read_json_bytes(http_get(url + ".sig", timeout=20, retries=2))
    ok, kid, why = verify_bytes(pubkeys, data, sig)
    if not ok:
        raise AzuGetError("signature refusée pour %s : %s" % (url, why))
    m = read_json_bytes(data)
    validate_manifest(m, project)
    return m, kid


def state_path(project: str, override=None) -> Path:
    return Path(override) if override else Path.home() / ".azuget" / "state" / ("%s.json" % project)


def cmd_check(args) -> int:
    cfg = load_config()
    feeds = args.feed or cfg.get("feed_urls") or []
    if not feeds:
        raise AzuGetError("aucun flux : --feed URL (ou feed_urls dans la config)")
    pubkeys = load_pubkeys(args.pubkey or default_pubkey_sources(cfg))
    sp = state_path(args.project, args.state)
    state = read_json_bytes(sp.read_bytes()) if sp.exists() else {}
    installed = args.installed or state.get("installed")
    errors = []
    found = None
    for base in feeds:
        try:
            m, kid = fetch_manifest(base, args.project, pubkeys)
        except AzuGetError as exc:
            errors.append("%s : %s" % (base, exc))
            continue
        last_pub = state.get("last_published")
        if last_pub and parse_iso(m["published"]) < parse_iso(last_pub):
            errors.append("%s : manifeste plus ancien (%s) que le dernier accepté (%s) : refusé (anti-retour en arrière)" % (base, m["published"], last_pub))
            continue
        found = (base, m, kid)
        break
    result = {"project": args.project, "installed": installed, "feeds_tried": feeds, "errors": errors}
    if not found:
        result["status"] = "unreachable"
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("aucun flux exploitable pour %s :" % args.project)
            for e in errors:
                print("  - " + e)
        return EXIT_BAD_SIGNATURE if any("signature" in e for e in errors) else EXIT_ERROR
    base, m, kid = found
    update = installed is None or version_cmp(m["version"], installed) > 0
    result.update({"feed": base, "key_id": kid, "latest": m["version"], "published": m["published"], "channel": m["channel"],
                   "update_available": update, "notes": m.get("notes"), "assets": m["assets"]})
    downloaded = []
    if args.download and update:
        out = Path(args.download)
        out.mkdir(parents=True, exist_ok=True)
        for a in m["assets"]:
            if args.platform and a.get("platform") not in (args.platform, "any"):
                continue
            dest = out / a["name"]
            last_exc = None
            for u in asset_candidate_urls(base, m, a):
                try:
                    http_download(u, dest, a["sha256"].lower(), a["size"])
                    downloaded.append({"name": a["name"], "from": u, "path": str(dest)})
                    if not args.json:
                        print("téléchargé et vérifié : %s (%s) depuis %s" % (dest, human_size(a["size"]), u))
                    break
                except AzuGetError as exc:
                    last_exc = exc
                    if not args.json:
                        print("  essai suivant : %s" % exc)
            else:
                raise AzuGetError("impossible de récupérer %s (%s)" % (a["name"], last_exc))
        result["downloaded"] = downloaded
    if not args.no_state:
        state.update({"installed": installed, "last_published": m["published"], "last_seen_version": m["version"], "checked": now_iso(), "feed": base})
        write_atomic(sp, canonical_json(state))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("%s : dernière version %s (%s, publiée le %s, flux %s, clé %s)" % (args.project, m["version"], m["channel"], m["published"], base, kid))
        if installed:
            print("installée : %s -> %s" % (installed, "MISE À JOUR DISPONIBLE" if update else "à jour"))
        else:
            print("aucune version installée connue -> MISE À JOUR DISPONIBLE")
        for a in m["assets"]:
            print("  %s  %s  %s  sha256 %s..." % (a["name"], a.get("platform", "any"), human_size(a["size"]), a["sha256"][:12]))
        for e in errors:
            print("  (flux ignoré : %s)" % e)
    return EXIT_UPDATE_AVAILABLE if update else EXIT_OK


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def cmd_status(args) -> int:
    cfg = load_config()
    feeds = args.feed or cfg.get("feed_urls") or []
    if not feeds:
        raise AzuGetError("aucun flux : --feed URL (ou feed_urls dans la config)")
    rc = EXIT_OK
    for base in feeds:
        base = base.rstrip("/")
        print("== %s" % base)
        try:
            st = read_json_bytes(http_get(base + "/status.json", timeout=10, retries=1))
            print("   hôte %s, synchronisé le %s, %s, %d Mo libres, commit %s" % (
                st.get("host"), st.get("time"), "OK" if st.get("ok") else "ERREURS", st.get("disk_free_mb", 0), (st.get("commit") or "?")[:10]))
            for pid, p in sorted((st.get("projects") or {}).items()):
                print("   %-20s %-10s fichiers en miroir : %s" % (pid, p.get("latest"), ", ".join(sorted(p.get("files", {}).keys())) or "-"))
            for e in st.get("errors") or []:
                print("   ! %s" % e)
            for url, peer in sorted((st.get("peers") or {}).items()):
                print("   pair %s : %s" % (url, "joignable (%s)" % peer.get("time") if peer.get("ok") else "INJOIGNABLE"))
            if not st.get("ok"):
                rc = EXIT_ERROR
        except AzuGetError:
            try:
                idx = read_json_bytes(http_get(base + "/v1/index.json", timeout=10, retries=1))
                print("   pas de status.json (flux statique) ; index généré le %s" % idx.get("generated"))
                for p in idx.get("projects", []):
                    print("   %-20s %-10s %s" % (p.get("id"), p.get("version"), p.get("published")))
            except AzuGetError as exc:
                print("   injoignable : %s" % exc)
                rc = EXIT_ERROR
    return rc


# ---------------------------------------------------------------------------
# mirror : côté Raspberry Pi
# ---------------------------------------------------------------------------

class Mirror:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.source = cfg["source"]
        self.branch = cfg.get("branch", "main")
        self.feed_subdir = cfg.get("feed_subdir", DEFAULT_FEED_SUBDIR)
        self.dest = Path(cfg.get("dest", "/srv/azuget"))
        self.state_dir = Path(cfg.get("state_dir", "/var/lib/azuget"))
        self.inbox = Path(cfg.get("inbox", "/srv/azuget-inbox"))
        self.pubkeys = load_pubkeys(cfg.get("pubkeys"))
        self.keep = int(cfg.get("keep_versions", 3))
        self.max_asset = int(cfg.get("max_asset_mb", 4096)) * 1024 * 1024
        self.min_free = int(cfg.get("min_free_mb", 1024)) * 1024 * 1024
        self.peers = cfg.get("peers", [])
        self.errors = []
        self.warnings = []
        self.commit = None
        self.verified_db_path = self.state_dir / "verified.json"
        self.verified_db = {}
        if self.verified_db_path.exists():
            try:
                self.verified_db = read_json_bytes(self.verified_db_path.read_bytes())
            except AzuGetError:
                self.verified_db = {}

    def error(self, msg):
        log("ERREUR " + msg)
        self.errors.append(msg)

    def warn(self, msg):
        log("attention " + msg)
        self.warnings.append(msg)

    # --- 1. dépôt de flux ---------------------------------------------------
    def update_repo(self) -> Path:
        repo = self.state_dir / "repo"
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", HOME=str(self.state_dir))
        if not (repo / ".git").exists():
            if repo.exists():
                shutil.rmtree(repo)
            log("clone de %s" % self.source)
            proc = run([which("git"), "clone", "-q", "--branch", self.branch, self.source, str(repo)], capture=True, check=False, env=env)
            if proc.returncode != 0:
                self.error("clone impossible : %s" % proc.stderr.decode("utf-8", "replace").strip()[-300:])
                return repo
        else:
            proc = run([which("git"), "-C", str(repo), "fetch", "-q", "--force", "origin", self.branch], capture=True, check=False, env=env, timeout=600)
            if proc.returncode != 0:
                self.warn("fetch impossible, flux local conservé : %s" % proc.stderr.decode("utf-8", "replace").strip()[-300:])
            else:
                run([which("git"), "-C", str(repo), "reset", "-q", "--hard", "origin/%s" % self.branch], capture=True, env=env)
        proc = run([which("git"), "-C", str(repo), "rev-parse", "HEAD"], capture=True, check=False, env=env)
        if proc.returncode == 0:
            self.commit = proc.stdout.decode().strip()
        return repo

    # --- 2. manifestes vérifiés -> dest/v1 -------------------------------------
    def sync_manifests(self, repo: Path) -> dict:
        src = repo / self.feed_subdir / "v1"
        dst = self.dest / "v1"
        verified = {}
        if not src.exists():
            self.error("dossier %s absent dans le dépôt" % (self.feed_subdir + "/v1"))
            return verified
        src_rel = set()
        for p in iter_feed_json(src):
            rel = p.relative_to(src).as_posix()
            src_rel.add(rel)
            src_rel.add(rel + ".sig")
            ok, kid, why = verify_file(self.pubkeys, p)
            if not ok:
                self.error("manifeste refusé : %s (%s)" % (rel, why))
                continue
            data = p.read_bytes()
            if p.name == "latest.json" or p.parent.name == "releases":
                try:
                    validate_manifest(read_json_bytes(data))
                except AzuGetError as exc:
                    self.error("manifeste refusé : %s (%s)" % (rel, exc))
                    continue
            verified[rel] = data
            for name, blob in ((rel, data), (rel + ".sig", p.with_name(p.name + ".sig").read_bytes())):
                target = dst / name
                if not target.exists() or target.read_bytes() != blob:
                    write_atomic(target, blob)
                    log("mis à jour : v1/%s" % name)
        # fichiers du flux qui ont disparu de la source (pas les fichiers binaires en miroir)
        if dst.exists() and self.commit:
            for p in dst.rglob("*"):
                if p.is_file() and p.suffix in (".json", ".sig") and "files" not in p.relative_to(dst).parts:
                    rel = p.relative_to(dst).as_posix()
                    if rel not in src_rel:
                        p.unlink()
                        log("retiré : v1/%s" % rel)
        for extra in ("index.html",):
            s = repo / self.feed_subdir / extra
            if s.exists():
                data = s.read_bytes()
                t = self.dest / extra
                if not t.exists() or t.read_bytes() != data:
                    write_atomic(t, data)
        return verified

    # --- 3. fichiers binaires ---------------------------------------------------
    def wanted_manifests(self, verified: dict):
        """-> {project: [manifest, ...]} : latest + les (keep-1) versions précédentes."""
        wanted = {}
        projects = sorted({rel.split("/")[0] for rel in verified if "/" in rel})
        for pid in projects:
            latest = verified.get("%s/latest.json" % pid)
            if not latest:
                continue
            chosen = [read_json_bytes(latest)]
            vers = verified.get("%s/versions.json" % pid)
            if vers:
                for v in read_json_bytes(vers).get("versions", []):
                    if len(chosen) >= self.keep:
                        break
                    if v.get("version") == chosen[0]["version"]:
                        continue
                    data = verified.get("%s/%s" % (pid, v.get("manifest", "")))
                    if data:
                        chosen.append(read_json_bytes(data))
            wanted[pid] = chosen
        return wanted

    def free_bytes(self) -> int:
        return shutil.disk_usage(str(self.dest)).free

    def place_asset(self, m: dict, a: dict) -> bool:
        pid, ver, name = m["project"], m["version"], a["name"]
        key = "%s/%s/%s" % (pid, ver, name)
        target = self.dest / "v1" / pid / "files" / ver / name
        sha = a["sha256"].lower()
        if target.exists():
            if target.stat().st_size == a["size"] and self.verified_db.get(key) == sha:
                return True
            got, size = sha256_file(target)
            if got == sha and size == a["size"]:
                self.verified_db[key] = sha
                return True
            self.warn("fichier en miroir corrompu, remplacé : %s" % key)
            target.unlink()
        if a["size"] > self.max_asset:
            self.warn("fichier ignoré, plus grand que max_asset_mb : %s (%s)" % (key, human_size(a["size"])))
            return False
        inbox_file = self.inbox / pid / ver / name
        if inbox_file.exists():
            got, size = sha256_file(inbox_file)
            if got == sha and size == a["size"]:
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.replace(inbox_file, target)
                except OSError:
                    shutil.copy2(inbox_file, target)
                    inbox_file.unlink()
                os.chmod(target, 0o644)
                self.verified_db[key] = sha
                log("adopté depuis la boîte de dépôt : %s" % key)
                return True
            self.warn("fichier déposé mais non conforme au manifeste, supprimé : %s" % key)
            inbox_file.unlink()
        if self.free_bytes() - a["size"] < self.min_free:
            self.warn("pas assez de place pour %s (%s)" % (key, human_size(a["size"])))
            return False
        for attempt in range(2):
            if attempt:
                time.sleep(8)
            for url in a.get("urls", []):
                try:
                    log("téléchargement : %s" % url)
                    http_download(url, target, sha, a["size"], timeout=120)
                    self.verified_db[key] = sha
                    return True
                except AzuGetError as exc:
                    self.warn("%s" % exc)
        self.error("fichier introuvable sur toutes les sources : %s" % key)
        return False

    def sync_assets(self, wanted: dict) -> dict:
        summary = {}
        for pid, manifests in wanted.items():
            files = {}
            for m in manifests:
                present = []
                for a in m["assets"]:
                    if self.place_asset(m, a):
                        present.append(a["name"])
                files[m["version"]] = present
            summary[pid] = {"latest": manifests[0]["version"], "published": manifests[0]["published"], "channel": manifests[0]["channel"], "files": files}
            # élagage des anciennes versions
            keep_versions = {m["version"] for m in manifests}
            fdir = self.dest / "v1" / pid / "files"
            if fdir.exists():
                for d in fdir.iterdir():
                    if d.is_dir() and d.name not in keep_versions:
                        shutil.rmtree(d, ignore_errors=True)
                        log("élagué : %s/files/%s" % (pid, d.name))
                        for k in [k for k in self.verified_db if k.startswith("%s/%s/" % (pid, d.name))]:
                            del self.verified_db[k]
        # boîte de dépôt : nettoyage des dossiers vides
        if self.inbox.exists():
            for d in sorted(self.inbox.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                if d.is_dir():
                    try:
                        d.rmdir()
                    except OSError:
                        pass
        write_atomic(self.verified_db_path, canonical_json(self.verified_db))
        return summary

    # --- 4. pairs et état --------------------------------------------------------
    def peers_status(self) -> dict:
        out = {}
        for url in self.peers:
            base = url.rstrip("/")
            try:
                st = read_json_bytes(http_get(base + "/status.json", timeout=8, retries=1))
                out[base] = {"ok": True, "time": st.get("time"), "host": st.get("host"), "sync_ok": st.get("ok"),
                             "latest": {pid: p.get("latest") for pid, p in (st.get("projects") or {}).items()}}
            except AzuGetError as exc:
                out[base] = {"ok": False, "error": str(exc)}
                self.warn("pair injoignable : %s" % base)
        return out

    def write_status(self, summary: dict, peers: dict) -> None:
        st = {
            "azuget": AZUGET_FORMAT,
            "host": socket.gethostname(),
            "time": now_iso(),
            "ok": not self.errors,
            "errors": self.errors[:20],
            "warnings": self.warnings[:20],
            "source": self.source,
            "commit": self.commit,
            "public_base": self.cfg.get("public_base"),
            "disk_free_mb": self.free_bytes() // (1024 * 1024),
            "keep_versions": self.keep,
            "projects": summary,
            "peers": peers,
            "tool": TOOL_VERSION,
        }
        write_atomic(self.dest / "status.json", canonical_json(st))

    def run(self) -> int:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.dest.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_dir / "lock"
        import fcntl  # Linux seulement
        with open(lock_path, "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                log("une synchronisation est déjà en cours")
                return EXIT_OK
            repo = self.update_repo()
            verified = self.sync_manifests(repo) if (repo / ".git").exists() else {}
            wanted = self.wanted_manifests(verified)
            summary = self.sync_assets(wanted)
            peers = self.peers_status()
            self.write_status(summary, peers)
        log("synchronisation terminée : %d projet(s), %d erreur(s), %d avertissement(s)" % (len(summary), len(self.errors), len(self.warnings)))
        return EXIT_ERROR if self.errors else EXIT_OK


def cmd_mirror(args) -> int:
    cfg = read_json_bytes(Path(args.config).read_bytes())
    return Mirror(cfg).run()


# ---------------------------------------------------------------------------
# github-setup
# ---------------------------------------------------------------------------

def cmd_github_setup(args) -> int:
    cfg = load_config(required=True)
    gh = which("gh")
    if run([gh, "auth", "status"], capture=True, check=False).returncode != 0:
        raise AzuGetError("gh n'est pas connecté : lance « gh auth login » (navigateur) puis recommence")
    feed_root = Path(cfg["feed_dir"])
    repo = args.repo
    if "/" not in repo:
        login = run([gh, "api", "user", "--jq", ".login"], capture=True).stdout.decode().strip()
        repo = "%s/%s" % (login, repo)
    owner, name = repo.split("/", 1)
    user = read_json_bytes(run([gh, "api", "user"], capture=True).stdout)
    if user.get("login", "").lower() == owner.lower():
        git(["config", "user.email", "%s+%s@users.noreply.github.com" % (user["id"], user["login"])], cwd=feed_root)
        if not git(["config", "user.name"], cwd=feed_root, check=False).stdout.strip():
            git(["config", "user.name", user.get("name") or user["login"]], cwd=feed_root)
    remotes = git(["remote"], cwd=feed_root).stdout.decode().split()
    exists = run([gh, "repo", "view", repo, "--json", "name"], capture=True, check=False).returncode == 0
    if not exists:
        log("création du dépôt %s (%s)" % (repo, args.visibility))
        run([gh, "repo", "create", repo, "--%s" % args.visibility, "--description", args.description, "--disable-wiki"], capture=True)
    url = "https://github.com/%s.git" % repo
    if "github" in remotes:
        git(["remote", "set-url", "github", url], cwd=feed_root)
    else:
        git(["remote", "add", "github", url], cwd=feed_root)
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=feed_root).stdout.decode().strip()
    git(["push", "-u", "github", "HEAD:%s" % branch], cwd=feed_root)
    log("poussé vers %s" % url)
    pages = run([gh, "api", "-X", "POST", "repos/%s/pages" % repo, "-f", "source[branch]=%s" % branch, "-f", "source[path]=/%s" % cfg.get("feed_subdir", DEFAULT_FEED_SUBDIR)], capture=True, check=False)
    if pages.returncode != 0 and b"409" not in pages.stderr and b"already" not in pages.stderr.lower():
        run([gh, "api", "-X", "PUT", "repos/%s/pages" % repo, "-f", "source[branch]=%s" % branch, "-f", "source[path]=/%s" % cfg.get("feed_subdir", DEFAULT_FEED_SUBDIR)], capture=True)
    pages_url = "https://%s.github.io/%s" % (owner.lower(), name)
    cfg["github_repo"] = repo
    cfg["github_branch"] = branch
    feeds = [u for u in cfg.get("feed_urls", []) if u.rstrip("/") != pages_url]
    cfg["feed_urls"] = [pages_url] + feeds
    if "github" not in cfg.get("default_hosts", []):
        cfg["default_hosts"] = ["github"] + [h for h in cfg.get("default_hosts", []) if h != "github"]
    save_config(cfg)
    run([gh, "repo", "edit", repo, "--homepage", pages_url], capture=True, check=False)
    print("dépôt : https://github.com/%s" % repo)
    print("flux GitHub Pages (actif après 1 à 10 min) : %s/v1/index.json" % pages_url)
    print("config mise à jour : github_repo, feed_urls, default_hosts = github d'abord")
    return EXIT_OK


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def cmd_selftest(args) -> int:
    ed25519, _, _ = _crypto()
    failures = []
    total = []

    def check(cond, label):
        print("%s  %s" % ("ok " if cond else "KO ", label))
        total.append(label)
        if not cond:
            failures.append(label)

    priv = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate()
    pub = public_raw(priv)
    keys = {key_id_of(pub): pub}
    data = canonical_json({"azuget": 1, "x": "é"})
    sig = sign_bytes(priv, data)
    check(verify_bytes(keys, data, sig)[0], "signature valide acceptée")
    check(not verify_bytes(keys, data + b" ", sig)[0], "octet ajouté -> refusé")
    check(not verify_bytes(keys, data.replace(b"1", b"2"), sig)[0], "contenu modifié -> refusé")
    check(not verify_bytes({key_id_of(public_raw(other)): public_raw(other)}, data, sig)[0], "autre clé -> refusé")
    bad = dict(sig, sig=sig["sig"][:-2] + ("00" if sig["sig"][-2:] != "00" else "11"))
    check(not verify_bytes(keys, data, bad)[0], "signature altérée -> refusée")
    check(not verify_bytes(keys, data, {"azuget_sig": 1, "alg": "rsa", "key_id": sig["key_id"], "sig": sig["sig"]})[0], "algorithme inattendu -> refusé")
    check(len(key_id_of(pub)) == 16, "key_id sur 16 caractères")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "m.json"
        p.write_bytes(data)
        sign_file(priv, p)
        check(verify_file(keys, p)[0], "fichier + .sig vérifiés")
        p.write_bytes(data + b"\n")
        check(not verify_file(keys, p)[0], "fichier modifié après signature -> refusé")
        seedf = Path(td) / "k.key"
        from cryptography.hazmat.primitives import serialization
        seedf.write_text("# test\n" + priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex() + "\n")
        check(public_raw(load_private_key(seedf)) == pub, "clé privée relue depuis le fichier hexadécimal")
    order = ["0.9", "1.0.0-alpha", "1.0.0-beta.2", "1.0.0-beta.10", "1.0.0", "1.0.1", "1.2", "1.10.0", "2.0.0-rc.1", "2.0.0", "v2.0.1"]
    check(sorted(order, key=version_key) == order, "ordre des versions : " + " < ".join(order))
    check(version_cmp("1.2", "1.2.0") == 0, "1.2 == 1.2.0")
    check(version_cmp("1.2.3+build7", "1.2.3") == 0, "métadonnées +build ignorées")
    for v, ok in (("1.0.0", True), ("1.0.0-beta.1", True), ("1.0.0-beta_1", False), ("1..0", False), ("a.b", False)):
        check(bool(VERSION_RE.match(v)) == ok, "syntaxe version %s -> %s" % (v, "acceptée" if ok else "refusée"))
    for pid, ok in (("mon-jeu", True), ("azuget-demo", True), ("Jeu", False), ("-x", False), ("a b", False)):
        check(bool(PROJECT_RE.match(pid)) == ok, "identifiant %s -> %s" % (pid, "accepté" if ok else "refusé"))
    m = {"azuget": 1, "project": "p", "version": "1.0.0", "published": now_iso(), "channel": "stable",
         "assets": [{"name": "a.zip", "size": 1, "sha256": "0" * 64, "urls": ["https://x/a.zip"]}]}
    try:
        validate_manifest(m, "p")
        check(True, "manifeste minimal valide")
    except AzuGetError as exc:
        check(False, "manifeste minimal valide (%s)" % exc)
    try:
        validate_manifest(m, "autre")
        check(False, "projet différent -> refusé")
    except AzuGetError:
        check(True, "projet différent -> refusé")
    check(asset_candidate_urls("http://pi/", m, m["assets"][0]) == ["http://pi/v1/p/files/1.0.0/a.zip", "https://x/a.zip"], "ordre des URL : miroir puis absolues")
    print("%d test(s), %d échec(s)" % (len(total), len(failures)))
    return EXIT_OK if not failures else EXIT_ERROR


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="azuget", description="AzuGet v1 : flux de mises à jour signées pour les projets d'Azura.")
    p.add_argument("--version", action="version", version="azuget " + TOOL_VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="crée la paire de clés Ed25519")
    s.add_argument("--dir", help="dossier de sortie (défaut : ~/.azuget/keys)")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("sign", help="signe des fichiers JSON")
    s.add_argument("files", nargs="+")
    s.add_argument("--key")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="vérifie des fichiers JSON ou tout le flux")
    s.add_argument("files", nargs="*")
    s.add_argument("--feed-dir", help="racine du dépôt de flux (défaut : feed_dir de la config)")
    s.add_argument("--pubkey", action="append", help="clé publique (hexadécimal ou fichier), répétable")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("init-feed", help="prépare docs/v1 (index.json, keys.json, .nojekyll)")
    s.add_argument("--feed-dir")
    s.add_argument("--key")
    s.set_defaults(func=cmd_init_feed)

    s = sub.add_parser("publish", help="publie une version d'un projet")
    s.add_argument("--project", required=True)
    s.add_argument("--version", required=True, dest="version")
    s.add_argument("--asset", action="append", default=[], help="CHEMIN|plateforme|type (ex. build/x.zip|windows-x64|full), répétable")
    s.add_argument("--name", help="nom affiché du projet")
    s.add_argument("--channel", help="stable (défaut), beta...")
    s.add_argument("--notes", help="notes de version (texte)")
    s.add_argument("--notes-file")
    s.add_argument("--notes-url")
    s.add_argument("--min-launcher")
    s.add_argument("--host", help="pi, github ou pi,github (défaut : default_hosts de la config)")
    s.add_argument("--repo", help="dépôt GitHub owner/nom qui héberge la release (défaut : github_repo)")
    s.add_argument("--tag", help="tag de la release GitHub (défaut : vVERSION, ou PROJET-vVERSION dans le dépôt du flux)")
    s.add_argument("--key")
    s.add_argument("--feed-dir")
    s.add_argument("--force", action="store_true", help="réécrit une version déjà publiée")
    s.add_argument("--force-latest", action="store_true", help="impose cette version comme dernière même si elle est plus ancienne")
    s.add_argument("--no-push", action="store_true")
    s.add_argument("--no-kick", action="store_true", help="ne réveille pas les miroirs par SSH")
    s.add_argument("--wait", type=int, default=0, help="attend jusqu'à N s que les flux de la config servent la version")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_publish)

    s = sub.add_parser("check", help="comme un lanceur : y a-t-il une mise à jour ?")
    s.add_argument("--project", required=True)
    s.add_argument("--feed", action="append", help="URL de base d'un flux, répétable (défaut : feed_urls de la config)")
    s.add_argument("--installed", help="version installée")
    s.add_argument("--pubkey", action="append")
    s.add_argument("--platform")
    s.add_argument("--download", help="dossier où télécharger et vérifier les fichiers")
    s.add_argument("--state", help="fichier d'état (défaut : ~/.azuget/state/PROJET.json)")
    s.add_argument("--no-state", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("status", help="état des miroirs")
    s.add_argument("--feed", action="append")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("mirror", help="(Raspberry Pi) synchronise le miroir")
    s.add_argument("--config", default="/etc/azuget/mirror.json")
    s.set_defaults(func=cmd_mirror)

    s = sub.add_parser("github-setup", help="crée le dépôt GitHub et GitHub Pages depuis le dépôt local")
    s.add_argument("--repo", default="azuget", help="owner/nom ou nom seul (compte connecté)")
    s.add_argument("--visibility", default="public", choices=["public", "private"])
    s.add_argument("--description", default="AzuGet : flux de mises à jour signées pour les projets d'Azura")
    s.set_defaults(func=cmd_github_setup)

    s = sub.add_parser("selftest", help="autotests")
    s.set_defaults(func=cmd_selftest)
    return p


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except AzuGetError as exc:
        die(str(exc))
    except KeyboardInterrupt:
        die("interrompu", 130)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
