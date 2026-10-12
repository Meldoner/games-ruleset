#!/usr/bin/env python3
"""
Builds a Mihomo rule-provider (behavior: classical) from executable names
of games in Discord's public "detectable applications" list.

Source: https://discord.com/api/v9/applications/detectable
Mihomo rules: https://wiki.metacubex.one/en/config/rules/

Only the Python standard library is used.

Examples:
    python discord_games_to_mihomo.py                       # -> games.yaml
    python discord_games_to_mihomo.py -o games.txt --format text
    python discord_games_to_mihomo.py --os all --comments
    python discord_games_to_mihomo.py --input detectable.json --extra my_games.txt
    python discord_games_to_mihomo.py --path-rules --case-insensitive
    python discord_games_to_mihomo.py --collapse-ue   # one regex for Unreal *-Shipping.exe
    python discord_games_to_mihomo.py --anticheat     # + EAC, BattlEye, Vanguard, FACEIT, ...

Config usage:
    find-process-mode: always   # or strict
    rule-providers:
      games:
        type: file              # or http with url:
        behavior: classical
        format: yaml            # text, if --format text
        path: ./ruleset/games.yaml
    rules:
      - RULE-SET,games,PROXY
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

DISCORD_URL = "https://discord.com/api/v9/applications/detectable"

# Names that are too generic: a PROCESS-NAME rule for them would catch
# unrelated programs (browsers, runtimes, launchers of everything).
DEFAULT_DENYLIST = {
    "game.exe", "launcher.exe", "client.exe", "start.exe", "setup.exe",
    "main.exe", "app.exe", "run.exe", "play.exe", "update.exe", "updater.exe",
    "java.exe", "javaw.exe", "python.exe", "pythonw.exe", "node.exe",
    "electron.exe", "chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe",
    "cmd.exe", "powershell.exe", "conhost.exe", "rundll32.exe", "svchost.exe",
    "dosbox.exe", "scummvm.exe", "nw.exe", "love.exe", "unitycrashhandler64.exe",
    "unitycrashhandler32.exe", "crashreportclient.exe", "steam.exe",
    "steamwebhelper.exe", "wine", "wine64", "java", "python", "python3", "mono",
    "bash", "sh",
}

# Unreal Engine shipping builds: <Name>-Win64-Shipping.exe, 32-bit and Game Pass (GDK) variants.
UE_SHIPPING_RE = r"(?i)-win(?:64|32|gdk)-shipping\.exe$"
UE_SHIPPING_RULE = f"PROCESS-NAME-REGEX,{UE_SHIPPING_RE}"

# Anti-cheat services and launchers (process names on Windows).
# Some names are from memory, not a database: check them in Task Manager.
ANTICHEAT_NAMES = [
    # Easy Anti-Cheat
    "start_protected_game.exe", "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe", "BattleBitEAC.exe",
    # BattlEye
    "BEService.exe", "BEService_x64.exe", "TslGame_BE.exe",
    "EscapeFromTarkov_BE.exe", "EscapeFromTarkovArena_BE.exe",
    # PUBG
    "TslGame_ZK.exe",
    # Riot Vanguard
    "vgc.exe", "vgm.exe", "vgtray.exe",
    # FACEIT
    "faceitservice.exe", "faceitclient.exe",
    # Anti-Cheat Expert
    "SGuard64.exe", "SGuardSvc64.exe", "SGuardUpdate64.exe", "ACE-Service64.exe",
    # EA Javelin
    "EAAntiCheat.GameService.exe", "EAAntiCheat.GameServiceLauncher.exe",
    # nProtect GameGuard / XIGNCODE3
    "GameMon.des", "GameMon64.des", "xcoronahost.xem",
]

# Path rules from the cheat sheet: catch everything in game library folders.
PATH_RULES = [
    r"PROCESS-PATH-REGEX,(?i).*[\\/]steamapps[\\/]common[\\/].*",
    r"PROCESS-PATH-REGEX,(?i).*[\\/]Epic Games[\\/].*",
    r"PROCESS-PATH-REGEX,(?i).*[\\/]Riot Games[\\/].*",
]


def rx_escape(s: str) -> str:
    """Escape only regex metacharacters (Go RE2 rejects escapes like '\\ ')."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", s)


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def fetch_discord(timeout: int = 60) -> list[dict]:
    req = urllib.request.Request(
        DISCORD_URL,
        headers={
            "User-Agent": "Mozilla/5.0 (mihomo-rules-builder)",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8"))


def load_json(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def normalize_exe(name: str) -> str | None:
    """Discord stores names like '>bf4.exe' or 'steamapps/common/x/bin/x.exe'.
    Mihomo PROCESS-NAME matches only the file name, so take the basename."""
    name = name.strip().lstrip(">").strip()
    name = name.replace("\\", "/").rstrip("/")
    base = name.rsplit("/", 1)[-1].strip()
    if not base or base in {".", ".."}:
        return None
    # Commas break the rule syntax; control chars are junk.
    if "," in base or any(ord(c) < 32 for c in base):
        return None
    return base


def collect(apps: list[dict], oses: set[str] | None, include_launchers: bool,
            denylist: set[str]) -> tuple[dict[str, set[str]], dict[str, int]]:
    """Returns {exe_name: {game names}} and counters for the report."""
    result: dict[str, set[str]] = defaultdict(set)
    stats = defaultdict(int)
    for app in apps:
        stats["apps"] += 1
        exes = app.get("executables") or []
        if not exes:
            stats["apps_without_exe"] += 1
            continue
        game = str(app.get("name") or app.get("id") or "?")
        added = False
        for ex in exes:
            if oses is not None and ex.get("os") not in oses:
                continue
            if ex.get("is_launcher") and not include_launchers:
                stats["skipped_launcher"] += 1
                continue
            base = normalize_exe(str(ex.get("name", "")))
            if not base:
                continue
            if base.lower() in denylist:
                stats["skipped_generic"] += 1
                continue
            result[base].add(game)
            added = True
        if added:
            stats["apps_used"] += 1
    return result, stats


def load_extra(paths: list[Path]) -> dict[str, set[str]]:
    """Extra list: one exe per line, '#' starts a comment."""
    out: dict[str, set[str]] = defaultdict(set)
    for p in paths:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            base = normalize_exe(line) if line else None
            if base:
                out[base].add(f"extra:{p.name}")
    return out


def make_rule(exe: str, case_insensitive: bool) -> str:
    if case_insensitive:
        return f"PROCESS-NAME-REGEX,(?i)^{rx_escape(exe)}$"
    return f"PROCESS-NAME,{exe}"


def yaml_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def render(exe_map: dict[str, set[str]], fmt: str, comments: bool,
           case_insensitive: bool, extra_rules: list[str], header: list[str]) -> str:
    # With case-insensitive matching, names differing only by case are duplicates.
    if case_insensitive:
        merged: dict[str, set[str]] = {}
        for exe, games in exe_map.items():
            key = exe.lower()
            merged.setdefault(key, set()).update(games)
        exe_map = merged

    header = header + [f"Rules: {len(exe_map) + len(extra_rules)}"]
    lines = [f"# {h}" for h in header]
    if fmt == "yaml":
        lines.append("payload:")
        for r in extra_rules:
            lines.append(f"  - {yaml_quote(r)}")
        for exe in sorted(exe_map, key=str.lower):
            if comments:
                games = sorted(exe_map[exe])
                shown = ", ".join(games[:3]) + (f" (+{len(games) - 3})" if len(games) > 3 else "")
                lines.append(f"  # {shown.replace(chr(10), ' ')}")
            lines.append(f"  - {yaml_quote(make_rule(exe, case_insensitive))}")
    else:  # text: one rule per line
        lines.extend(extra_rules)
        for exe in sorted(exe_map, key=str.lower):
            lines.append(make_rule(exe, case_insensitive))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Discord detectable -> Mihomo rule-provider")
    ap.add_argument("-o", "--output", type=Path, default=Path("games.yaml"))
    ap.add_argument("--format", choices=["yaml", "text"], default="yaml",
                    help="rule-provider format (default: yaml)")
    ap.add_argument("--input", type=Path,
                    help="use a saved detectable.json instead of downloading")
    ap.add_argument("--save-json", type=Path,
                    help="save the downloaded JSON (for reuse with --input)")
    ap.add_argument("--os", default="win32",
                    help="win32, linux, darwin, comma-separated, or 'all' (default: win32)")
    ap.add_argument("--include-launchers", action="store_true",
                    help="include executables marked is_launcher")
    ap.add_argument("--no-denylist", action="store_true",
                    help="do not filter generic names (game.exe, java.exe, ...)")
    ap.add_argument("--deny", type=Path, action="append", default=[],
                    help="file with extra names to exclude, one per line")
    ap.add_argument("--extra", type=Path, action="append", default=[],
                    help="file with extra exe names to add, one per line")
    ap.add_argument("--comments", action="store_true",
                    help="(yaml) add game names as comments above each rule")
    ap.add_argument("--collapse-ue", action="store_true",
                    help="replace all *-Win64/Win32/WinGDK-Shipping.exe names with one "
                         "PROCESS-NAME-REGEX rule (Unreal Engine games)")
    ap.add_argument("--anticheat", action="store_true",
                    help="add built-in anti-cheat process rules (EAC, BattlEye, Vanguard, "
                         "FACEIT, ACE, Javelin, GameGuard, XIGNCODE)")
    ap.add_argument("--case-insensitive", action="store_true",
                    help="emit PROCESS-NAME-REGEX,(?i)^name$ instead of PROCESS-NAME "
                         "(slower with thousands of rules)")
    ap.add_argument("--path-rules", action="store_true",
                    help="also add PROCESS-PATH-REGEX rules for Steam/Epic/Riot folders")
    args = ap.parse_args()

    if args.input:
        apps = load_json(args.input)
        source = str(args.input)
    else:
        log(f"Downloading {DISCORD_URL} ...")
        try:
            apps = fetch_discord()
        except Exception as e:  # noqa: BLE001
            log(f"Download failed: {e}")
            return 1
        source = DISCORD_URL
        if args.save_json:
            args.save_json.write_text(json.dumps(apps, ensure_ascii=False), encoding="utf-8")
            log(f"Saved JSON to {args.save_json}")

    if not isinstance(apps, list):
        log("Unexpected JSON: expected a list of applications")
        return 1

    oses = None if args.os.strip().lower() == "all" else {
        o.strip() for o in args.os.split(",") if o.strip()}

    denylist = set() if args.no_denylist else set(DEFAULT_DENYLIST)
    for p in args.deny:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                denylist.add(line)

    exe_map, stats = collect(apps, oses, args.include_launchers, denylist)
    for exe, games in load_extra(args.extra).items():
        if exe.lower() not in denylist:
            exe_map.setdefault(exe, set()).update(games)

    extra_rules: list[str] = []
    if args.collapse_ue:
        ue = re.compile(UE_SHIPPING_RE)
        before = len(exe_map)
        exe_map = {e: g for e, g in exe_map.items() if not ue.search(e)}
        log(f"Collapsed {before - len(exe_map)} Unreal Shipping names into one regex rule")
        extra_rules.append(UE_SHIPPING_RULE)
    if args.anticheat:
        ac = {n.lower() for n in ANTICHEAT_NAMES}
        # Anti-cheat names are allowed even if they look generic; drop duplicates from the game list.
        exe_map = {e: g for e, g in exe_map.items() if e.lower() not in ac}
        extra_rules.extend(make_rule(n, args.case_insensitive) for n in ANTICHEAT_NAMES)
    if args.path_rules:
        extra_rules.extend(PATH_RULES)

    header = [
        "Mihomo rule-provider (behavior: classical)",
        f"Source: {source}",
        f"Generated: {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"OS filter: {args.os}",
    ]
    text = render(exe_map, args.format, args.comments, args.case_insensitive,
                  extra_rules, header)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")

    log(f"Apps total: {stats['apps']}, without executables: {stats['apps_without_exe']}, "
        f"used: {stats['apps_used']}")
    log(f"Skipped launchers: {stats['skipped_launcher']}, generic names: {stats['skipped_generic']}")
    log(f"Wrote {len(exe_map)} unique names to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
