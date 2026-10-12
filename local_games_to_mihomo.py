#!/usr/bin/env python3
"""
Collects game executable names from local Windows game-detection databases
and builds a Mihomo rule-provider (behavior: classical).

Sources (run on Windows; each can be disabled or pointed to a file manually):
  1. NVIDIA fingerprint.db   - game database of GeForce Experience / NVIDIA App.
                               XML (<FingerprintDB><Fingerprint>...); if the local
                               file is compressed or binary, exe names are extracted
                               heuristically.
  2. KnownGameList.bin       - Microsoft list used by Xbox Game Bar / Game Mode.
                               Undocumented binary: exe names are extracted as
                               UTF-16 / ASCII strings.
  3. Registry GameConfigStore - games Windows has already detected on this PC
                               (HKCU\\System\\GameConfigStore\\Children, MatchedExeFullPath).

Files are found automatically in the usual folders; if not, pass them explicitly:
    python local_games_to_mihomo.py --fingerprint "C:/path/fingerprint.db" --known "C:/path/KnownGameList.bin"

Examples:
    python local_games_to_mihomo.py                      # -> local_games.yaml
    python local_games_to_mihomo.py --comments --collapse-ue
    python local_games_to_mihomo.py --names-out names.txt   # for discord_games_to_mihomo.py --extra
    python local_games_to_mihomo.py --list-sources          # only show which files were found

Only the Python standard library is used.
"""

from __future__ import annotations

PARSER_VERSION = 5  # bumped on parser fixes; all_games_to_mihomo.py checks it

import argparse
import datetime as dt
import gzip
import html
import lzma
import os
import re
import sys
import zlib
from pathlib import Path

# ---------- settings ----------

GENERIC_NAMES = {
    "game.exe", "launcher.exe", "client.exe", "start.exe", "setup.exe", "main.exe",
    "app.exe", "run.exe", "play.exe", "update.exe", "updater.exe", "java.exe",
    "javaw.exe", "python.exe", "pythonw.exe", "node.exe", "nw.exe", "electron.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe", "cmd.exe",
    "powershell.exe", "conhost.exe", "rundll32.exe", "svchost.exe", "dosbox.exe",
    "scummvm.exe", "love.exe", "steam.exe", "steamwebhelper.exe",
    "unitycrashhandler64.exe", "unitycrashhandler32.exe", "crashreportclient.exe",
    "unins000.exe", "uninstall.exe", "vcredist_x64.exe", "vcredist_x86.exe",
    "dxsetup.exe", "dxwebsetup.exe", "applicationframehost.exe",
}
UE_SHIPPING_RE = r"(?i)-win(?:64|32|gdk)-shipping\.exe$"

# Valid Windows exe file name: no path separators or reserved characters.
EXE_RE = r"[A-Za-z0-9 _.\-+()\[\]!&'~#@$%^{}=]{1,120}\.exe"
EXE_FULL = re.compile(rf"^{EXE_RE}$", re.I)
# For free text (commands, mixed strings): no spaces, otherwise "1 foo.exe" gets glued.
EXE_WORD = r"[A-Za-z0-9_.\-+()\[\]!&'~#@$%^{}=]{1,120}\.exe"


def is_junk(exe: str) -> bool:
    """Generic or too short to be a safe PROCESS-NAME: game.exe, 2.exe, q.exe."""
    stem = exe[:-4]
    return exe.lower() in GENERIC_NAMES or stem.isdigit() or len(stem) < 2


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def env_path(var: str) -> Path | None:
    v = os.environ.get(var)
    return Path(v) if v else None


# ---------- locating files ----------

def find_files(names: list[str], roots: list[Path], max_depth: int = 6) -> list[Path]:
    """Search for files by name (case-insensitive) under roots, limited depth."""
    wanted = {n.lower() for n in names}
    found: list[Path] = []
    for root in roots:
        if not root or not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            if len(Path(dirpath).parts) - base_depth >= max_depth:
                dirnames[:] = []
            for f in filenames:
                if f.lower() in wanted:
                    found.append(Path(dirpath) / f)
    # unique, newest first
    uniq = {p.resolve(): p for p in found}
    return sorted(uniq.values(), key=lambda p: p.stat().st_mtime, reverse=True)


def fingerprint_candidates() -> list[Path]:
    roots = [
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NVIDIA Corporation",
        (env_path("LOCALAPPDATA") or Path()) / "NVIDIA Corporation",
        (env_path("LOCALAPPDATA") or Path()) / "NVIDIA",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "NVIDIA Corporation",
    ]
    return find_files(["fingerprint.db", "fingerprint.db.xml", "fingerprint.xml"], roots)


def known_list_candidates() -> list[Path]:
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    local = env_path("LOCALAPPDATA")
    roots = [
        windir / "broker",
        local / "Microsoft" if local else None,
        local / "Packages" if local else None,
        local,
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft",
    ]
    return find_files(["KnownGameList.bin"], [r for r in roots if r], max_depth=5)


# ---------- decoding helpers ----------

def maybe_decompress(data: bytes) -> bytes:
    for fn in (gzip.decompress, zlib.decompress, lzma.decompress,
               lambda d: zlib.decompress(d, -15)):
        try:
            out = fn(data)
            if out:
                return out
        except Exception:  # noqa: BLE001
            pass
    return data


def as_text(data: bytes) -> str | None:
    """Returns text if the data looks like (UTF-8 / UTF-16) text, else None."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", errors="ignore")
    if len(data) > 1 and data[1:200:2].count(0) > 80:  # UTF-16LE without BOM
        return data.decode("utf-16-le", errors="ignore")
    head = data[:4096]
    if head and sum(32 <= b < 127 or b in (9, 10, 13) for b in head) / len(head) > 0.95:
        return data.decode("utf-8", errors="ignore")
    return None


JUNK_LEAD = set("$%&(.@^!#~'+=-)]}")


def _is_len_prefix(ch: str, rest: str) -> bool:
    """KnownGameList.bin stores a length before each string: in UTF-16 bytes (2 x chars)
    or chars. When that number is a printable code ('$' = 36 for an 18-char name),
    it looks like part of the name."""
    return ord(ch) in (len(rest), 2 * len(rest))


def clean_name(n: str) -> str:
    """Removes a leftover length-prefix or junk symbol in front of an exe name."""
    if len(n) > 5 and EXE_FULL.match(n[1:]) and (n[1].isalnum() or n[1] in "{[_"):
        if _is_len_prefix(n[0], n[1:]) or n[0] in JUNK_LEAD:
            return n[1:]
    return n


def _from_piece(p: str) -> str | None:
    """p is a text fragment ending with '.exe' (may have other fields glued in front)."""
    p = basename(p)
    # Leftmost position where a length prefix matches the rest -> longest real name.
    for i in range(len(p) - 5):
        ch, rest = p[i], p[i + 1:]
        # Inside the fragment only a symbol can be a prefix; letters, digits and spaces
        # there are far more likely part of the name ("A Very Long ... .exe").
        if i > 0 and (ch.isalnum() or ch == " "):
            continue
        if ch != " " and _is_len_prefix(ch, rest) and EXE_FULL.match(rest) \
                and (rest[0].isalnum() or rest[0] in "{[_"):
            return rest
    if EXE_FULL.match(p):
        return clean_name(p)
    m = re.findall(EXE_WORD, p, re.I)
    return clean_name(m[-1]) if m else None


def _from_string(s: str, out: set[str]) -> None:
    """Splits a printable run at every '.exe' and extracts one name per piece."""
    pos = 0
    for m in re.finditer(r"\.exe(?![A-Za-z0-9_])", s, re.I):
        name = _from_piece(s[pos:m.end()])
        if name:
            out.add(name)
        pos = m.end()


def strings_exe(data: bytes) -> set[str]:
    """Extracts exe-like strings from binary data (ASCII and UTF-16LE, both alignments)."""
    out: set[str] = set()
    for m in re.finditer(rb"[\x20-\x7e]{5,260}", data):
        _from_string(m.group().decode("ascii"), out)
    for buf in (data, data[1:]):
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,260}", buf):
            _from_string(m.group().decode("utf-16-le"), out)
    return out


def basename(s: str) -> str:
    return s.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().strip('"')


# ---------- sources ----------

def parse_fingerprint(path: Path, include_apps: bool = False) -> tuple[dict[str, set[str]], str]:
    """Returns ({exe: {game names}}, mode)."""
    data = maybe_decompress(path.read_bytes())
    text = as_text(data)
    result: dict[str, set[str]] = {}

    def add(exe: str, game: str) -> None:
        exe = basename(html.unescape(exe))
        if EXE_FULL.match(exe):
            result.setdefault(exe, set()).add(game)

    if text and "<Fingerprint" in text:
        # Regex instead of ElementTree: tolerates truncated / slightly broken XML.
        blocks = re.split(r"<Fingerprint[\s>]", text)[1:]
        skipped_apps = 0
        for b in blocks:
            b = b.split("</Fingerprint>", 1)[0]
            m = re.search(r"<DisplayName>\s*(.*?)\s*</DisplayName>", b, re.S)
            n = re.match(r"""\s*name\s*=\s*['"]([^'"]*)['"]""", b)
            game = html.unescape(m.group(1) if m else (n.group(1) if n else "?"))
            # NVIDIA marks non-games (VLC, Blender, VS Code, OBS ...) as creative apps.
            if not include_apps and re.search(
                    r"<IsCreativeApplication>\s*(?:true|1)\s*</IsCreativeApplication>", b, re.I):
                skipped_apps += 1
                continue
            for tag in ("DriverProfile", "Image", "Exe", "Executable"):
                for v in re.findall(rf"<{tag}>\s*(.*?)\s*</{tag}>", b, re.S):
                    for part in re.split(r"[;|,]", v):
                        add(part, game)
            # <File name='x.exe' /> and similar attributes
            for v in re.findall(r"""<File\b[^>]*?\bname\s*=\s*['"]([^'"]+)['"]""", b, re.I):
                add(v, game)
            # exe names mentioned anywhere else in the block (e.g. Launch commands)
            for v in re.findall(EXE_WORD, re.sub(r"<[^>]+>", " ", b), re.I):
                add(v, game)
        apps = "" if include_apps else f", {skipped_apps} creative apps skipped"
        return result, f"xml, {len(blocks) - skipped_apps} entries{apps}"

    # Unknown / encrypted format: fall back to string extraction.
    for exe in strings_exe(data):
        add(exe, "NVIDIA fingerprint")
    return result, "binary strings (format not recognized, names only)"


def parse_known_list(path: Path) -> dict[str, set[str]]:
    data = maybe_decompress(path.read_bytes())
    return {basename(e): {"Xbox KnownGameList"} for e in strings_exe(data)
            if EXE_FULL.match(basename(e))}


def read_gameconfigstore() -> dict[str, set[str]]:
    """Games Windows Game Bar has detected on this PC."""
    try:
        import winreg
    except ImportError:
        return {}
    out: dict[str, set[str]] = {}
    root = r"System\GameConfigStore\Children"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, root)
    except OSError:
        return {}
    with key:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(key, sub) as k:
                    vals = {}
                    j = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, j)
                        except OSError:
                            break
                        vals[name] = val
                        j += 1
            except OSError:
                continue
            exe = vals.get("MatchedExeFullPath") or vals.get("ExeFullPath")
            if isinstance(exe, str) and exe.lower().endswith(".exe"):
                game = str(vals.get("GameDVR_GameName") or vals.get("TitleId") or "Game Bar")
                out.setdefault(basename(exe), set()).add(f"{game} (detected on this PC)")
    return out


# ---------- output ----------

def q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def render(exes: dict[str, set[str]], args, sources: list[str]) -> str:
    rules: list[tuple[str, str]] = []
    if args.collapse_ue:
        rules.append(("Unreal Engine shipping builds", f"PROCESS-NAME-REGEX,{UE_SHIPPING_RE}"))
    for e in sorted(exes, key=str.lower):
        g = sorted(exes[e])
        rules.append((", ".join(g[:3]) + (f" (+{len(g) - 3})" if len(g) > 3 else ""),
                      f"PROCESS-NAME,{e}"))
    out = ["# Mihomo rule-provider (behavior: classical)"]
    out += [f"# Source: {s}" for s in sources]
    out += [f"# Generated: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}",
            f"# Rules: {len(rules)}"]
    if args.format == "yaml":
        out.append("payload:")
        for c, r in rules:
            if args.comments:
                out.append(f"  # {c.replace(chr(10), ' ')}")
            out.append(f"  - {q(r)}")
    else:
        out += [r for _, r in rules]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="NVIDIA fingerprint.db + Xbox KnownGameList.bin -> Mihomo rules")
    ap.add_argument("--fingerprint", type=Path, action="append", default=[],
                    help="path to NVIDIA fingerprint.db (auto-detected if omitted)")
    ap.add_argument("--known", type=Path, action="append", default=[],
                    help="path to KnownGameList.bin (auto-detected if omitted)")
    ap.add_argument("--no-nvidia", action="store_true")
    ap.add_argument("--nvidia-apps", action="store_true",
                    help="keep NVIDIA entries marked IsCreativeApplication (VLC, Blender ...)")
    ap.add_argument("--no-xbox", action="store_true")
    ap.add_argument("--no-registry", action="store_true", help="skip GameConfigStore registry")
    ap.add_argument("--list-sources", action="store_true", help="only print found files and exit")
    ap.add_argument("-o", "--output", type=Path, default=Path("local_games.yaml"))
    ap.add_argument("--format", choices=["yaml", "text"], default="yaml")
    ap.add_argument("--comments", action="store_true", help="(yaml) game names above rules")
    ap.add_argument("--collapse-ue", action="store_true",
                    help="one regex rule instead of all *-Win64-Shipping.exe names")
    ap.add_argument("--keep-generic", action="store_true", help="keep names like game.exe")
    ap.add_argument("--names-out", type=Path, help="also write a plain exe list")
    args = ap.parse_args()

    fps = [] if args.no_nvidia else (args.fingerprint or fingerprint_candidates())
    kgl = [] if args.no_xbox else (args.known or known_list_candidates())
    if args.list_sources:
        print("NVIDIA fingerprint:", *(fps or ["not found"]), sep="\n  ")
        print("Xbox KnownGameList:", *(kgl or ["not found"]), sep="\n  ")
        return 0

    exes: dict[str, set[str]] = {}
    sources: list[str] = []

    def merge(part: dict[str, set[str]]) -> None:
        for e, g in part.items():
            exes.setdefault(e, set()).update(g)

    for p in fps[:1] if not args.fingerprint else fps:  # newest auto-found file only
        try:
            part, mode = parse_fingerprint(p, args.nvidia_apps)
        except OSError as e:
            log(f"NVIDIA: cannot read {p}: {e}")
            continue
        log(f"NVIDIA: {p} -> {len(part)} exe names ({mode})")
        sources.append(f"NVIDIA {p.name} ({mode})")
        merge(part)
    if not fps and not args.no_nvidia:
        log("NVIDIA: fingerprint.db not found (use --fingerprint PATH)")

    for p in kgl[:1] if not args.known else kgl:
        try:
            part = parse_known_list(p)
        except OSError as e:
            log(f"Xbox: cannot read {p}: {e}")
            continue
        log(f"Xbox: {p} -> {len(part)} exe names")
        sources.append(f"Xbox {p.name}")
        merge(part)
    if not kgl and not args.no_xbox:
        log("Xbox: KnownGameList.bin not found (use --known PATH)")

    if not args.no_registry:
        part = read_gameconfigstore()
        if part:
            log(f"Registry GameConfigStore: {len(part)} exe names")
            sources.append("Registry HKCU\\System\\GameConfigStore")
            merge(part)

    # Case-insensitive dedupe (Windows names are case-insensitive), keep first spelling.
    merged: dict[str, tuple[str, set[str]]] = {}
    for e, g in exes.items():
        k = e.lower()
        if k in merged:
            merged[k][1].update(g)
        else:
            merged[k] = (e, set(g))
    exes = {e: g for e, g in merged.values()}

    if not args.keep_generic:
        exes = {e: g for e, g in exes.items() if not is_junk(e)}
    if args.collapse_ue:
        ue = re.compile(UE_SHIPPING_RE)
        exes = {e: g for e, g in exes.items() if not ue.search(e)}

    if not exes:
        log("Nothing collected.")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(exes, args, sources), encoding="utf-8")
    if args.names_out:
        args.names_out.write_text("\n".join(sorted(exes, key=str.lower)) + "\n", encoding="utf-8")
    log(f"Wrote {len(exes)} exe names to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
