#!/usr/bin/env python3
"""
Builds a Mihomo rule-provider (behavior: classical) from Steam app configs:
the same data SteamDB shows on /app/<id>/config/ (installdir + launch options),
fetched directly from Steam PICS with an anonymous login. SteamDB itself is
not scraped (it forbids crawling and sits behind Cloudflare).

Requirements:
    pip install "steam-next[client]"     # maintained fork of ValvePython/steam
    (the original "steam[client]" also works where it installs)

Where app IDs come from (combine freely):
    --appid 1808500 --appid 570         explicit IDs
    --appids-file ids.txt               one ID per line ('#' comments allowed)
    --steam-library "D:/SteamLibrary"   installed games (steamapps/appmanifest_*.acf);
                                        repeat for every library folder
    --all --api-key KEY                 every game on Steam via IStoreService/GetAppList
                                        (key: https://steamcommunity.com/dev/apikey).
                                        ~150k+ apps, takes a while; use --cache.

Examples:
    python steam_games_to_mihomo.py --appid 1808500
    python steam_games_to_mihomo.py --steam-library "C:/Program Files (x86)/Steam" --path-rules
    python steam_games_to_mihomo.py --all --api-key XXXX --cache steam_cache.json --comments

Output can be merged with discord_games_to_mihomo.py: write a plain list with
--names-out names.txt and pass it there as --extra names.txt.

Note on Unreal Engine games: the launch exe (e.g. PioneerGame.exe for ARC Raiders)
is often a small stub that starts <Name>-Win64-Shipping.exe, the process that
actually uses the network. Use --path-rules (one rule per game folder, catches
every exe inside) or --ue-shipping (adds the guessed Shipping name).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

GENERIC_NAMES = {
    "game.exe", "launcher.exe", "client.exe", "start.exe", "setup.exe",
    "main.exe", "app.exe", "run.exe", "play.exe", "update.exe", "updater.exe",
    "java.exe", "javaw.exe", "python.exe", "pythonw.exe", "node.exe", "nw.exe",
    "electron.exe", "dosbox.exe", "scummvm.exe", "love.exe", "steam.exe",
    "cmd.exe", "powershell.exe", "explorer.exe", "rundll32.exe", "unins000.exe",
    "vcredist_x64.exe", "vcredist_x86.exe", "dxsetup.exe", "uninstall.exe",
}
SKIP_LAUNCH_TYPES = {"editor", "server", "none"}   # override with --launch-types all
GAME_TYPES = {"game"}                              # --types game,application,demo ...
STEAM_PATH_RULE = r"PROCESS-PATH-REGEX,(?i).*[\\/]steamapps[\\/]common[\\/].*"


def rx_escape(s: str) -> str:
    """Escape only regex metacharacters (Go RE2 rejects escapes like '\\ ')."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", s)


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------- app ID sources ----------

def ids_from_file(path: Path) -> set[int]:
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line.isdigit():
            out.add(int(line))
    return out


def ids_from_library(root: Path) -> set[int]:
    """Reads appmanifest_<id>.acf from a Steam library (root or its steamapps)."""
    steamapps = root if root.name.lower() == "steamapps" else root / "steamapps"
    ids = set()
    for f in steamapps.glob("appmanifest_*.acf"):
        m = re.match(r"appmanifest_(\d+)\.acf$", f.name)
        if m:
            ids.add(int(m.group(1)))
    # Other libraries listed in libraryfolders.vdf
    vdf = steamapps / "libraryfolders.vdf"
    if vdf.exists():
        for p in re.findall(r'"path"\s+"([^"]+)"', vdf.read_text(encoding="utf-8", errors="ignore")):
            other = Path(p.replace("\\\\", "\\")) / "steamapps"
            if other.resolve() != steamapps.resolve() and other.is_dir():
                for f in other.glob("appmanifest_*.acf"):
                    m = re.match(r"appmanifest_(\d+)\.acf$", f.name)
                    if m:
                        ids.add(int(m.group(1)))
    return ids


def ids_from_store(api_key: str) -> set[int]:
    """All games via IStoreService/GetAppList (paginated, needs a Web API key)."""
    ids, last = set(), 0
    while True:
        q = urllib.parse.urlencode({
            "key": api_key, "include_games": "true", "include_dlc": "false",
            "include_software": "false", "include_videos": "false",
            "include_hardware": "false", "max_results": 50000, "last_appid": last,
        })
        url = f"https://api.steampowered.com/IStoreService/GetAppList/v1/?{q}"
        with urllib.request.urlopen(url, timeout=60) as r:
            resp = json.load(r).get("response", {})
        apps = resp.get("apps", [])
        ids.update(a["appid"] for a in apps)
        log(f"  GetAppList: {len(ids)} apps so far")
        if not resp.get("have_more_results"):
            return ids
        last = resp.get("last_appid", apps[-1]["appid"] if apps else last)


# ---------- PICS ----------

def fetch_appinfo(ids: list[int], cache: dict[str, dict], chunk: int, cache_path: Path | None) -> None:
    """Fills cache {appid: {name, type, installdir, launch}} from Steam PICS."""
    todo = [i for i in ids if str(i) not in cache]
    if not todo:
        return
    from steam.client import SteamClient  # imported lazily: only needed for fetching

    client = SteamClient()
    log("Logging in to Steam anonymously ...")
    if client.anonymous_login() != 1:  # EResult.OK
        raise RuntimeError("anonymous login failed")
    try:
        for n in range(0, len(todo), chunk):
            part = todo[n:n + chunk]
            for attempt in range(3):
                try:
                    info = client.get_product_info(apps=part, timeout=60) or {}
                    break
                except Exception as e:  # noqa: BLE001
                    log(f"  retry {attempt + 1}: {e}")
                    time.sleep(5)
                    if not client.logged_on:
                        client.anonymous_login()
            else:
                log(f"  giving up on {len(part)} apps starting at {part[0]}")
                continue
            for appid, a in (info.get("apps") or {}).items():
                common, config = a.get("common") or {}, a.get("config") or {}
                cache[str(appid)] = {
                    "name": common.get("name", ""),
                    "type": str(common.get("type", "")).lower(),
                    "installdir": config.get("installdir", ""),
                    "launch": list((config.get("launch") or {}).values()),
                }
            for appid in part:  # remember apps PICS returned nothing for
                cache.setdefault(str(appid), {"name": "", "type": "", "installdir": "", "launch": []})
            log(f"  PICS: {min(n + chunk, len(todo))}/{len(todo)}")
            if cache_path:
                cache_path.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    finally:
        client.logout()


# ---------- extraction ----------

def exe_basename(path: str) -> str | None:
    p = path.strip().strip('"').replace("\\", "/")
    p = re.sub(r"^\./+", "", p)
    base = p.rsplit("/", 1)[-1].strip()
    if not base or "," in base or "://" in path:
        return None
    return base


def launch_os_ok(entry: dict, oses: set[str] | None) -> bool:
    if oses is None:
        return True
    oslist = str((entry.get("config") or {}).get("oslist", "")).lower()
    if not oslist:  # no oslist = all platforms
        return True
    return any(o in oses for o in oslist.split(","))


def extract(cache: dict[str, dict], ids: set[int], args) -> tuple[dict[str, set[str]], dict[str, str]]:
    """Returns ({exe: {game names}}, {installdir: game name})."""
    oses = None if args.os == "all" else set(args.os.split(","))
    types = None if args.types == "all" else set(args.types.split(","))
    skip_launch = set() if args.launch_types == "all" else SKIP_LAUNCH_TYPES
    exes: dict[str, set[str]] = {}
    dirs: dict[str, str] = {}
    for appid in sorted(ids):
        a = cache.get(str(appid))
        if not a or (types is not None and a["type"] not in types):
            continue
        name = a["name"] or str(appid)
        found = False
        for entry in a["launch"]:
            if not isinstance(entry, dict) or not launch_os_ok(entry, oses):
                continue
            if str(entry.get("type", "default")).lower() in skip_launch:
                continue
            raw = str(entry.get("executable", ""))
            base = exe_basename(raw)
            if not base:
                continue
            low = base.lower()
            # On Windows only real executables make sense as process names.
            if oses == {"windows"} and not low.endswith(".exe"):
                continue
            if low in GENERIC_NAMES and not args.keep_generic:
                continue
            exes.setdefault(base, set()).add(name)
            found = True
            # UE stub usually sits in the game root and starts Binaries/Win64/<Name>-Win64-Shipping.exe
            at_root = "/" not in re.sub(r"^\\./+", "", raw.strip().replace("\\", "/"))
            if args.ue_shipping and at_root and low.endswith(".exe") and "-shipping" not in low:
                exes.setdefault(f"{base[:-4]}-Win64-Shipping.exe", set()).add(name + " (UE guess)")
        if a["installdir"] and (found or args.dirs_for_all):
            dirs[a["installdir"]] = name
    return exes, dirs


# ---------- output ----------

def rule_for_exe(exe: str, ci: bool) -> str:
    return f"PROCESS-NAME-REGEX,(?i)^{rx_escape(exe)}$" if ci else f"PROCESS-NAME,{exe}"


def rule_for_dir(d: str) -> str:
    return rf"PROCESS-PATH-REGEX,(?i).*[\\/]steamapps[\\/]common[\\/]{rx_escape(d)}[\\/].*"


def q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def render(exes, dirs, args, source: str) -> str:
    if args.case_insensitive:  # merge names that differ only by case
        merged: dict[str, set[str]] = {}
        for e, g in exes.items():
            merged.setdefault(e.lower(), set()).update(g)
        exes = merged
    rules: list[tuple[str, str]] = []  # (comment, rule)
    if args.path_rules == "all":
        rules.append(("all Steam games", STEAM_PATH_RULE))
    elif args.path_rules == "per-game":
        for d in sorted(dirs, key=str.lower):
            rules.append((dirs[d], rule_for_dir(d)))
    for e in sorted(exes, key=str.lower):
        g = sorted(exes[e])
        rules.append((", ".join(g[:3]) + (f" (+{len(g) - 3})" if len(g) > 3 else ""),
                      rule_for_exe(e, args.case_insensitive)))
    out = [
        "# Mihomo rule-provider (behavior: classical)",
        f"# Source: Steam PICS app config ({source})",
        f"# Generated: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}",
        f"# Rules: {len(rules)}",
    ]
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
    ap = argparse.ArgumentParser(description="Steam PICS app config -> Mihomo rule-provider")
    src = ap.add_argument_group("app IDs")
    src.add_argument("--appid", type=int, action="append", default=[])
    src.add_argument("--appids-file", type=Path, action="append", default=[])
    src.add_argument("--steam-library", type=Path, action="append", default=[],
                     help="Steam folder or library folder; reads installed games")
    src.add_argument("--all", action="store_true", help="all Steam games (needs --api-key)")
    src.add_argument("--api-key", help="Steam Web API key for --all")
    ap.add_argument("-o", "--output", type=Path, default=Path("steam_games.yaml"))
    ap.add_argument("--format", choices=["yaml", "text"], default="yaml")
    ap.add_argument("--cache", type=Path, help="JSON cache of fetched app configs (resumable)")
    ap.add_argument("--chunk", type=int, default=200, help="apps per PICS request")
    ap.add_argument("--os", default="windows", help="windows, linux, macos, comma-separated, or all")
    ap.add_argument("--types", default="game", help="app types: game,application,demo,tool... or all")
    ap.add_argument("--launch-types", default="playable", choices=["playable", "all"],
                    help="'playable' skips editor/server launch options")
    ap.add_argument("--keep-generic", action="store_true", help="keep names like game.exe, launcher.exe")
    ap.add_argument("--path-rules", choices=["none", "per-game", "all"], default="none",
                    help="per-game: PROCESS-PATH-REGEX for each game's installdir; "
                         "all: one rule for the whole steamapps/common")
    ap.add_argument("--dirs-for-all", action="store_true",
                    help="per-game path rules also for games without a usable exe")
    ap.add_argument("--ue-shipping", action="store_true",
                    help="also add <Name>-Win64-Shipping.exe guesses (Unreal Engine)")
    ap.add_argument("--case-insensitive", action="store_true")
    ap.add_argument("--comments", action="store_true")
    ap.add_argument("--names-out", type=Path, help="also write a plain exe list (for --extra)")
    args = ap.parse_args()
    args.os = args.os.lower()

    ids: set[int] = set(args.appid)
    for f in args.appids_file:
        ids |= ids_from_file(f)
    for lib in args.steam_library:
        found = ids_from_library(lib)
        log(f"{lib}: {len(found)} installed apps")
        ids |= found
    if args.all:
        if not args.api_key:
            ap.error("--all needs --api-key")
        log("Fetching app list from IStoreService/GetAppList ...")
        ids |= ids_from_store(args.api_key)
    if not ids:
        ap.error("no app IDs: use --appid, --appids-file, --steam-library or --all")

    cache: dict[str, dict] = {}
    if args.cache and args.cache.exists():
        cache = json.loads(args.cache.read_text(encoding="utf-8"))
        log(f"Cache: {len(cache)} apps")
    try:
        fetch_appinfo(sorted(ids), cache, args.chunk, args.cache)
    except ImportError:
        log('Missing library: pip install "steam-next[client]"')
        return 1
    except Exception as e:  # noqa: BLE001
        log(f"Steam request failed: {e}")
        if not any(str(i) in cache for i in ids):
            return 1
        log("Continuing with cached data")

    exes, dirs = extract(cache, ids, args)
    source = f"{len(ids)} app IDs"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(exes, dirs, args, source), encoding="utf-8")
    if args.names_out:
        args.names_out.write_text("\n".join(sorted(exes, key=str.lower)) + "\n", encoding="utf-8")
    log(f"Apps: {len(ids)}, exe names: {len(exes)}, game folders: {len(dirs)} -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
