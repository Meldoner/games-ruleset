#!/usr/bin/env python3
"""
Downloads the NVIDIA and Xbox game databases directly from their servers,
so the ruleset can be built without NVIDIA App / Game Bar (e.g. in GitHub Actions).

NVIDIA  fingerprint.db
    https://wpc-download.gfe.nvidia.com/static/<hash>/fingerprint.db
    The <hash> changes with every new database. The current link (and its sha256) comes
    from the public manifest https://ops-gx.nvidia.com/v3/applications/ontology/ontology.json
    (the same request NVIDIA App makes). The last used link is kept in
    sources/nvidia_url.txt as a fallback.

Xbox    KnownGameList
    https://dlassets-ssl.xboxlive.com/public/content/kgl/Version/<rev>/kgl.<rev>.compressed
    <rev> grows (not every number exists). The latest one is found by probing numbers
    after the last known revision (sources/xbox_rev.txt). The file is packed with the
    Windows Compression API (XPRESS = MS-XCA Plain LZ77) and contains JSON. It is
    unpacked in pure Python (works on Linux); on Windows cabinet.dll is the fallback.
    Check the pure-Python unpacker against Windows:  python remote_sources.py --selftest

Usable on its own for a quick check:
    python remote_sources.py            # prints what it finds, downloads nothing big twice
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
NVIDIA_DEFAULT_URL = "https://wpc-download.gfe.nvidia.com/static/21a4fd5d/fingerprint.db"
# Public manifest NVIDIA App uses to find the current database (found in NvBackend64.dll):
# {"version": "...", "files": [{"filename": "fingerprint.db", "url": ..., "sha256": ..., "size": ...}]}
NVIDIA_ONTOLOGY_API = "https://ops-gx.nvidia.com/v3/applications/ontology/ontology.json"
KGL_URL = "https://dlassets-ssl.xboxlive.com/public/content/kgl/Version/{rev}/kgl.{rev}.compressed"
KGL_DEFAULT_REV = 2673
KGL_MAX_GAP = 40          # stop probing after this many missing numbers in a row
MS_COMPRESS_MAGIC = b"\x0a\x51\xe5\xc0"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def http_get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status == 200
    except urllib.error.HTTPError:
        return False


# ---------------- NVIDIA ----------------

def nvidia_url_from_local() -> str | None:
    """Current fingerprint.db link from NVIDIA App's DAO cache (on a PC with NVIDIA App)."""
    dao = Path(os.environ.get("LOCALAPPDATA", "")) / "NVIDIA Corporation" / "NVIDIA app" / "NvBackend" / "DAO"
    metas = []
    try:
        cur = json.loads((dao / "state.json").read_text(encoding="utf-8")).get("c")
        if cur:
            metas.append(dao / cur / "metadata.json")
    except (OSError, ValueError):
        pass
    if dao.is_dir():
        metas += sorted(dao.glob("*/metadata.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for m in metas:
        try:
            meta = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for f in meta.get("metadata", {}).get("files", []):
            if f.get("filename", "").lower() == "fingerprint.db" and f.get("url"):
                return f["url"]
    return None


def nvidia_current() -> dict:
    """Current fingerprint.db entry from NVIDIA's public manifest: {url, sha256, size, version}."""
    meta = json.loads(http_get(NVIDIA_ONTOLOGY_API, timeout=60).decode("utf-8"))
    meta = meta.get("metadata", meta)
    for f in meta.get("files", []):
        if f.get("filename", "").lower() == "fingerprint.db" and f.get("url"):
            return {**f, "version": meta.get("version")}
    raise ValueError("fingerprint.db not listed in the ontology manifest")


def nvidia_download(url: str, sha256: str | None = None) -> bytes:
    import hashlib
    data = http_get(url)
    if sha256 and hashlib.sha256(data).hexdigest().lower() != sha256.lower():
        raise ValueError("sha256 mismatch for fingerprint.db")
    if b"<Fingerprint" not in data[:200000]:
        raise ValueError("downloaded file does not look like fingerprint.db")
    return data


def nvidia_parse(data: bytes, include_apps: bool = False):
    """Parses with local_games_to_mihomo.parse_fingerprint (same rules as for the local file)."""
    import local_games_to_mihomo as loc
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fingerprint.db"
        p.write_bytes(data)
        return loc.parse_fingerprint(p, include_apps)


# ---------------- Xbox ----------------

def kgl_latest(start_rev: int, max_gap: int = KGL_MAX_GAP) -> int | None:
    """Highest existing revision >= start_rev (probing upward, tolerating gaps)."""
    best = start_rev if http_exists(KGL_URL.format(rev=start_rev)) else None
    rev, misses = start_rev, 0
    while misses < max_gap:
        rev += 1
        if http_exists(KGL_URL.format(rev=rev)):
            best, misses = rev, 0
        else:
            misses += 1
    if best is None:  # start_rev itself may be gone: look a bit backwards
        for r in range(start_rev - 1, max(0, start_rev - max_gap), -1):
            if http_exists(KGL_URL.format(rev=r)):
                return r
    return best


# ---------- XPRESS (MS-XCA "Plain LZ77"), pure Python ----------

def lz77_plain_decompress(buf: bytes, out_limit: int | None = None) -> bytes:
    """MS-XCA 2.4 Plain LZ77 decompression (COMPRESS_ALGORITHM_XPRESS = 3)."""
    out = bytearray()
    n = len(buf)
    ip = 0
    flags = 0
    flag_count = 0
    last_half = 0  # position of the shared length nibble byte, 0 = none
    while True:
        if flag_count == 0:
            if ip + 4 > n:
                break
            flags = int.from_bytes(buf[ip:ip + 4], "little")
            ip += 4
            flag_count = 32
        flag_count -= 1
        if not (flags >> flag_count) & 1:
            if ip >= n:
                break
            out.append(buf[ip])
            ip += 1
        else:
            if ip >= n:
                break
            if ip + 2 > n:
                raise ValueError("truncated match")
            mb = buf[ip] | (buf[ip + 1] << 8)
            ip += 2
            length = mb & 7
            offset = (mb >> 3) + 1
            if length == 7:
                if last_half == 0:
                    if ip >= n:
                        raise ValueError("truncated length")
                    length = buf[ip] & 0x0F
                    last_half = ip
                    ip += 1
                else:
                    length = buf[last_half] >> 4
                    last_half = 0
                if length == 15:
                    if ip >= n:
                        raise ValueError("truncated length")
                    length = buf[ip]
                    ip += 1
                    if length == 255:
                        if ip + 2 > n:
                            raise ValueError("truncated length")
                        length = buf[ip] | (buf[ip + 1] << 8)
                        ip += 2
                        if length == 0:
                            if ip + 4 > n:
                                raise ValueError("truncated length")
                            length = int.from_bytes(buf[ip:ip + 4], "little")
                            ip += 4
                        if length < 15 + 7:
                            raise ValueError("bad length")
                        length -= 15 + 7
                    length += 15
                length += 7
            length += 3
            if offset > len(out):
                raise ValueError("match offset before start of output")
            start = len(out) - offset
            if offset >= length:
                out += out[start:start + length]
            else:  # overlapping copy
                for i in range(length):
                    out.append(out[start + i])
        if out_limit is not None and len(out) > out_limit:
            raise ValueError("output larger than expected")
    return bytes(out)


def _try_chunks(body: bytes, size_fmt: str, block: int) -> bytes | None:
    """Body = sequence of [compressed size][XPRESS data] chunks, each <= block bytes out."""
    import struct
    hdr = struct.calcsize(size_fmt)
    pos, out = 0, bytearray()
    while pos < len(body):
        if pos + hdr > len(body):
            return None
        sizes = struct.unpack_from(size_fmt, body, pos)
        csize = sizes[-1]
        pos += hdr
        if csize == 0 or pos + csize > len(body):
            return None
        chunk = body[pos:pos + csize]
        pos += csize
        try:
            dec = lz77_plain_decompress(chunk, out_limit=block)
        except ValueError:
            if len(sizes) > 1 and sizes[0] == csize:  # stored (uncompressed) chunk
                dec = chunk
            else:
                return None
        if len(sizes) > 1 and sizes[0] != len(dec):
            return None
        out += dec
    return bytes(out)


def ms_decompress_exact(data: bytes) -> bytes:
    """Layout verified on a real KGL file (kgl.2691): 24-byte header
    (magic, size 0x18, algorithm 3 = XPRESS, ..., block size 0x40000), then chunks
    [u32 compressed size][u32 uncompressed size][Plain LZ77 data], ending with 0/0."""
    import struct
    hsize = data[4]
    pos, out = hsize, bytearray()
    while pos + 8 <= len(data):
        csize, usize = struct.unpack_from("<II", data, pos)
        pos += 8
        if csize == 0 and usize == 0:
            break
        chunk = data[pos:pos + csize]
        if len(chunk) != csize:
            raise ValueError("truncated chunk")
        pos += csize
        dec = chunk if csize == usize else lz77_plain_decompress(chunk, out_limit=usize)
        if len(dec) != usize:
            raise ValueError(f"chunk size mismatch: {len(dec)} != {usize}")
        out += dec
    return bytes(out)


def ms_decompress_py(data: bytes, validate=None) -> bytes:
    """Windows Compression API buffer (magic 0A 51 E5 C0, XPRESS) -> bytes, without Windows.
    The container layout is undocumented, so plausible layouts are tried and the result
    is accepted only if validate(result) is true (e.g. it parses as JSON)."""
    if not data.startswith(MS_COMPRESS_MAGIC):
        return data
    hsize = data[4] if 8 <= data[4] <= 64 else 24
    block = int.from_bytes(data[16:20], "little") if len(data) >= 20 else 0
    if not 4096 <= block <= 64 * 1024 * 1024:
        block = 1 << 18
    body = data[hsize:]
    candidates = [("exact", lambda: ms_decompress_exact(data))]
    for fmt in ("<I", "<Q", "<II", "<QQ"):
        candidates.append((f"chunks {fmt}", lambda f=fmt: _try_chunks(body, f, block)))
    candidates.append(("single stream", lambda: lz77_plain_decompress(body)))
    for off in range(8, 40, 4):  # header of a different size
        if off != hsize:
            for fmt in ("<I", "<Q"):
                candidates.append((f"chunks {fmt} @{off}",
                                   lambda o=off, f=fmt: _try_chunks(data[o:], f, block)))
    for name, fn in candidates:
        try:
            res = fn()
        except Exception:  # noqa: BLE001
            res = None
        if res and (validate is None or validate(res)):
            return res
    raise RuntimeError("could not unpack the Windows Compression API buffer in pure Python")


def ms_decompress_win(data: bytes) -> bytes:
    """Same via cabinet.dll (Windows only)."""
    import ctypes
    from ctypes import wintypes
    cab = ctypes.WinDLL("cabinet.dll")
    algs = [data[7]] if len(data) > 7 and data[7] in (2, 3, 4, 5) else []
    for alg in algs + [a for a in (3, 4, 2, 5) if a not in algs]:
        h = wintypes.HANDLE()
        if not cab.CreateDecompressor(alg, None, ctypes.byref(h)):
            continue
        try:
            src = ctypes.create_string_buffer(data, len(data))
            need = ctypes.c_size_t(0)
            cab.Decompress(h, src, len(data), None, 0, ctypes.byref(need))
            if not need.value or need.value > 1_000_000_000:
                continue
            dst = ctypes.create_string_buffer(need.value)
            got = ctypes.c_size_t(0)
            if cab.Decompress(h, src, len(data), dst, need.value, ctypes.byref(got)):
                return dst.raw[:got.value]
        finally:
            cab.CloseDecompressor(h)
    raise RuntimeError("Windows Compression API could not unpack the KGL file")


def _is_json(b: bytes) -> bool:
    try:
        json.loads(b.decode("utf-8-sig"))
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def ms_decompress(data: bytes) -> bytes:
    """Pure Python first (works on Linux); cabinet.dll as a fallback on Windows."""
    if not data.startswith(MS_COMPRESS_MAGIC):
        return data
    try:
        return ms_decompress_py(data, validate=_is_json)
    except RuntimeError:
        if os.name == "nt":
            return ms_decompress_win(data)
        raise


NAME_KEYS = ("name", "title", "displayname", "gamename", "titlename", "productname", "working")
PLACEHOLDER = re.compile(r"^\$\{(.+)\}(\.exe)$", re.I)  # "${garden story}.exe" -> "garden story.exe"


def kgl_parse(raw: bytes) -> dict[str, set[str]]:
    """KGL JSON -> {exe: {game names}}. The schema is undocumented, so the JSON is walked:
    every string ending with .exe is taken (basename), with a name-like sibling as title."""
    import local_games_to_mihomo as loc
    doc = json.loads(raw.decode("utf-8-sig"))
    out: dict[str, set[str]] = {}

    def title_of(d: dict) -> str | None:
        for k, v in d.items():
            if k.lower() in NAME_KEYS and isinstance(v, str) and not v.lower().endswith(".exe"):
                return v
        return None

    def walk(node, title=None):
        if isinstance(node, dict):
            title = title_of(node) or title
            for v in node.values():
                walk(v, title)
        elif isinstance(node, list):
            for v in node:
                walk(v, title)
        elif isinstance(node, str) and node.lower().endswith(".exe"):
            exe = loc.basename(node)
            m = PLACEHOLDER.match(exe)
            if m:
                exe = m.group(1).strip() + m.group(2)
            if loc.EXE_FULL.match(exe):
                out.setdefault(exe, set()).add(title or "Xbox KnownGameList")

    walk(doc)
    return out


def kgl_sample(raw: bytes, n: int = 2) -> str:
    """First entries of the JSON, for checking the schema."""
    doc = json.loads(raw.decode("utf-8-sig"))
    entries = doc.get("entries") if isinstance(doc, dict) else None
    if isinstance(entries, list):
        return json.dumps({"version": doc.get("version"), "entries[:n]": entries[:n]},
                          ensure_ascii=False, indent=1)[:3000]
    return json.dumps(doc, ensure_ascii=False)[:3000]


def selftest(path: str | None) -> int:
    """Windows: compares the pure-Python unpacker with cabinet.dll on a real KGL file."""
    import hashlib
    import time
    if path:
        data = Path(path).read_bytes()
    else:
        rev = kgl_latest(KGL_DEFAULT_REV)
        data = http_get(KGL_URL.format(rev=rev))
        Path(f"kgl.{rev}.compressed").write_bytes(data)
    log(f"input: {len(data)} B, header {data[:24].hex(' ')}")
    t = time.time()
    try:
        py = ms_decompress_py(data, validate=_is_json)
        log(f"python: {len(py)} B sha256={hashlib.sha256(py).hexdigest()[:16]} ({time.time() - t:.1f}s)")
    except Exception as e:  # noqa: BLE001
        py = None
        log(f"python: FAILED {e}")
    if os.name == "nt":
        win = ms_decompress_win(data)
        log(f"windows: {len(win)} B sha256={hashlib.sha256(win).hexdigest()[:16]}")
        log("RESULT: " + ("OK, identical" if py == win else "MISMATCH, please send the .compressed file"))
        return 0 if py == win else 1
    log("RESULT: " + ("OK (valid JSON)" if py else "FAILED"))
    return 0 if py else 1


def find_nvidia_endpoint() -> int:
    """Windows: searches NVIDIA App files for the request that returns DAO metadata
    (the source of the static/<hash>/ link). Read-only; prints candidate strings."""
    roots = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "NVIDIA Corporation" / "NVIDIA app",
             Path(os.environ.get("LOCALAPPDATA", "")) / "NVIDIA Corporation" / "NVIDIA app"]
    pat = re.compile(r"wpc|\bdao\b|/dao|ontology|fingerprint|metadata", re.I)
    ascii_re = re.compile(rb"[\x20-\x7e]{6,400}")
    u16_re = re.compile(rb"(?:[\x20-\x7e]\x00){6,400}")
    seen: dict[str, str] = {}
    exts = {".dll", ".exe", ".js", ".json", ".html", ".cfg", ".xml", ".txt", ".ini"}
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in exts or "CefCache" in p.parts:
                continue
            try:
                if p.stat().st_size > 80 * 1024 * 1024:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            for rx, enc in ((ascii_re, "ascii"), (u16_re, "utf-16-le")):
                for m in rx.finditer(data):
                    t = m.group().decode(enc, "ignore").strip()
                    if pat.search(t) and ("/" in t or "http" in t or "%s" in t or "{" in t):
                        seen.setdefault(t[:300], p.name)
    lines = [f"{v}: {k}" for k, v in sorted(seen.items(), key=lambda kv: (kv[1], kv[0]))]
    Path("nvidia_endpoint.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"{len(lines)} candidate strings saved to nvidia_endpoint.txt")
    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--find-nvidia-endpoint":
        return find_nvidia_endpoint()
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        return selftest(sys.argv[2] if len(sys.argv) > 2 else None)
    if len(sys.argv) == 3 and sys.argv[1] == "--write-nvidia-url":
        # Used by update_sources.ps1 on the PC: store the current link if NVIDIA App knows it.
        url = nvidia_url_from_local()
        if not url:
            log("NVIDIA App DAO metadata not found; link not updated")
            return 1
        dst = Path(sys.argv[2])
        old = dst.read_text(encoding="utf-8").strip() if dst.exists() else ""
        if old != url:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(url + "\n", encoding="utf-8", newline="\n")
            log(f"NVIDIA link updated: {old or '(none)'} -> {url}")
        else:
            log("NVIDIA link unchanged")
        return 0
    sha = None
    try:
        cur = nvidia_current()
        url, sha = cur["url"], cur.get("sha256")
        log(f"NVIDIA manifest: version {cur.get('version')}")
    except Exception as e:  # noqa: BLE001
        log(f"NVIDIA manifest failed ({e}), using fallback link")
        url = nvidia_url_from_local() or NVIDIA_DEFAULT_URL
    log(f"NVIDIA url: {url}")
    try:
        part, mode = nvidia_parse(nvidia_download(url, sha))
        log(f"NVIDIA: {len(part)} exe names ({mode})")
    except Exception as e:  # noqa: BLE001
        log(f"NVIDIA failed: {e}")
    rev = kgl_latest(KGL_DEFAULT_REV)
    log(f"Xbox latest revision: {rev}")
    if rev:
        try:
            raw = ms_decompress(http_get(KGL_URL.format(rev=rev)))
            Path(f"kgl.{rev}.json").write_bytes(raw)
            log(f"Xbox: {len(raw)} bytes JSON saved to kgl.{rev}.json")
            log(kgl_sample(raw))
            log(f"Xbox: {len(kgl_parse(raw))} exe names")
        except Exception as e:  # noqa: BLE001
            log(f"Xbox failed: {e}")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
