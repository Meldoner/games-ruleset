#!/usr/bin/env python3
"""
One combined Mihomo rule-provider from all sources, without duplicates:
  - Discord detectable list   (discord_games_to_mihomo.py)
  - NVIDIA fingerprint.db      (local_games_to_mihomo.py)
  - Xbox KnownGameList.bin     (local_games_to_mihomo.py)
  - Windows GameConfigStore    (games Game Bar detected on this PC)
  - optional: any other rule files (--rules-in), e.g. output of steam_games_to_mihomo.py

Keep all three scripts in the same folder. Run on Windows for NVIDIA/Xbox sources.

Duplicates are removed case-insensitively (Windows file names ignore case):
bf4.exe from Discord and BF4.exe from NVIDIA become one rule. With --comments every
rule shows where it came from: [D]iscord, [N]VIDIA, [X]box, [R]egistry, [F]ile.

Examples:
    python all_games_to_mihomo.py --collapse-ue --anticheat
    python all_games_to_mihomo.py --collapse-ue --anticheat --comments -o games.yaml
    python all_games_to_mihomo.py --discord-json detectable.json --rules-in steam_games.yaml
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import discord_games_to_mihomo as dsc
    import local_games_to_mihomo as loc
    import remote_sources as rmt
except ImportError as e:
    sys.exit(f"Put discord_games_to_mihomo.py, local_games_to_mihomo.py and remote_sources.py next to this script ({e})")

# Older copies of local_games_to_mihomo.py had a KnownGameList.bin parsing bug
# (names like "$game.exe") and no is_junk(); refuse to run with them.
if getattr(loc, "PARSER_VERSION", 0) < 5:
    sys.exit("local_games_to_mihomo.py in this folder is outdated: replace it with the latest "
             "version (it fixes '$name.exe' / '&name.exe' garbage from KnownGameList.bin).")

log = loc.log
# Non-game programs that show up in Discord/NVIDIA/Xbox lists (recording, streaming,
# chat, media, creative tools, store launchers). Routing them through a game proxy
# is usually unwanted. Disable with --keep-apps, extend with --deny FILE.
NON_GAME_APPS = {
    # streaming / recording / overlays
    "obs.exe", "obs32.exe", "obs64.exe", "streamlabs obs.exe", "streamlabs desktop.exe",
    "xsplit.core.exe", "medal.exe", "outplayed.exe", "nvcontainer.exe", "nvidia share.exe",
    "nvidia broadcast.exe", "action.exe", "bandicam.exe", "fraps.exe", "shadowplay.exe",
    "gamebar.exe", "gamebarftserver.exe", "overwolf.exe", "rtss.exe", "msiafterburner.exe",
    # chat / calls
    "discord.exe", "discordptb.exe", "discordcanary.exe", "telegram.exe", "skype.exe",
    "slack.exe", "teams.exe", "ms-teams.exe", "zoom.exe", "ts3client_win64.exe",
    "ts3client_win32.exe", "teamspeak.exe", "mumble.exe", "whatsapp.exe", "viber.exe",
    # media
    "spotify.exe", "vlc.exe", "mpc-hc.exe", "mpc-hc64.exe", "mpc-be64.exe", "potplayer.exe",
    "potplayermini.exe", "potplayermini64.exe", "foobar2000.exe", "aimp.exe", "itunes.exe",
    "music.ui.exe", "wmplayer.exe", "netflix.exe", "kodi.exe", "plex.exe",
    # creative / dev tools
    "photoshop.exe", "illustrator.exe", "afterfx.exe", "adobe premiere pro.exe",
    "blender.exe", "gimp-2.10.exe", "krita.exe", "resolve.exe", "audacity.exe",
    "fl64.exe", "ableton live 11 suite.exe", "code.exe", "devenv.exe", "idea64.exe",
    "pycharm64.exe", "rider64.exe", "unity.exe", "unity hub.exe", "unrealeditor.exe",
    "ue4editor.exe", "godot.exe", "notepad++.exe", "sublime_text.exe", "figma.exe",
    # store launchers (big downloads should not go through a game proxy)
    "epicgameslauncher.exe", "eadesktop.exe", "origin.exe", "battle.net.exe",
    "galaxyclient.exe", "upc.exe", "ubisoftconnect.exe", "riotclientservices.exe",
    "steamservice.exe", "playnite.desktopapp.exe", "itch.exe", "xboxpcapp.exe",
    # system / misc
    "wallpaper32.exe", "wallpaper64.exe", "lively.exe", "msedgewebview2.exe",
    "searchhost.exe", "textinputhost.exe", "taskmgr.exe", "notepad.exe", "mspaint.exe",
}

TAGS = {"discord": "D", "nvidia": "N", "xbox": "X", "registry": "R", "file": "F"}


class Collector:
    """exe (lowercase key) -> spelling, sources, game names."""

    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.other_rules: dict[str, set[str]] = {}  # non PROCESS-NAME rules from --rules-in
        self.counts: dict[str, int] = {}

    def add(self, exe: str, source: str, games=()) -> None:
        exe = exe.strip()
        if not exe:
            return
        it = self.items.setdefault(exe.lower(), {"name": exe, "src": set(), "games": set()})
        it["src"].add(source)
        it["games"].update(g for g in games if not g.startswith(("Xbox ", "NVIDIA ")))
        self.counts[source] = self.counts.get(source, 0) + 1

    def add_map(self, mapping: dict[str, set[str]], source: str) -> None:
        for exe, games in mapping.items():
            self.add(exe, source, games)


# ---------- sources ----------
# Each live source returns ({exe: {games}}, label) or (None, None) when unavailable.

def from_discord(args):
    try:
        if args.discord_json:
            apps = dsc.load_json(args.discord_json)
        else:
            log("Discord: downloading ...")
            apps = dsc.fetch_discord()
            if args.save_json:
                import json
                args.save_json.write_text(json.dumps(apps, ensure_ascii=False), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        log(f"Discord: failed ({e})")
        return None, None
    exe_map, stats = dsc.collect(apps, {"win32"}, False, set())  # junk filtered later, once
    log(f"Discord: {len(exe_map)} exe names from {stats['apps_used']} games")
    return exe_map, "Discord detectable"


def _read_first_line(p: Path | None) -> str | None:
    try:
        return p.read_text(encoding="utf-8").strip() or None if p else None
    except OSError:
        return None


def from_nvidia(args):
    if args.remote:
        url_file = args.sources_dir / "nvidia_url.txt" if args.sources_dir else None
        url, sha = args.nvidia_url, None
        if not url:
            try:  # public manifest with the current link
                cur = rmt.nvidia_current()
                url, sha = cur["url"], cur.get("sha256")
            except Exception as e:  # noqa: BLE001
                log(f"NVIDIA: manifest failed ({e}), using the last known link")
                url = _read_first_line(url_file) or rmt.NVIDIA_DEFAULT_URL
        try:
            part, mode = rmt.nvidia_parse(rmt.nvidia_download(url, sha), args.nvidia_apps)
        except Exception as e:  # noqa: BLE001
            log(f"NVIDIA: download failed ({url}): {e}")
            return None, None
        log(f"NVIDIA: {url} -> {len(part)} exe names ({mode})")
        if url_file and part:
            url_file.parent.mkdir(parents=True, exist_ok=True)
            url_file.write_text(url + "\n", encoding="utf-8", newline="\n")
        return (part, "NVIDIA fingerprint.db") if part else (None, None)
    paths = args.fingerprint or loc.fingerprint_candidates()[:1]
    if not paths:
        log("NVIDIA: fingerprint.db not found")
        return None, None
    out: dict[str, set[str]] = {}
    for p in paths:
        try:
            part, mode = loc.parse_fingerprint(p, args.nvidia_apps)
        except OSError as e:
            log(f"NVIDIA: cannot read {p}: {e}")
            continue
        for k, v in part.items():
            out.setdefault(k, set()).update(v)
        log(f"NVIDIA: {p} -> {len(part)} exe names ({mode})")
    return (out, "NVIDIA fingerprint.db") if out else (None, None)


def from_xbox(args):
    if args.remote:
        rev_file = args.sources_dir / "xbox_rev.txt" if args.sources_dir else None
        start = args.kgl_rev or int(_read_first_line(rev_file) or rmt.KGL_DEFAULT_REV)
        try:
            rev = rmt.kgl_latest(start)
            if not rev:
                raise RuntimeError(f"no revision found near {start}")
            raw = rmt.ms_decompress(rmt.http_get(rmt.KGL_URL.format(rev=rev)))
            part = rmt.kgl_parse(raw)
        except Exception as e:  # noqa: BLE001
            log(f"Xbox: download failed: {e}")
            return None, None
        log(f"Xbox: revision {rev} -> {len(part)} exe names")
        if rev_file and part:
            rev_file.parent.mkdir(parents=True, exist_ok=True)
            rev_file.write_text(f"{rev}\n", encoding="utf-8", newline="\n")
        return (part, "Xbox KnownGameList") if part else (None, None)
    paths = args.known or loc.known_list_candidates()[:1]
    if not paths:
        log("Xbox: KnownGameList.bin not found")
        return None, None
    out: dict[str, set[str]] = {}
    for p in paths:
        try:
            part = loc.parse_known_list(p)
        except OSError as e:
            log(f"Xbox: cannot read {p}: {e}")
            continue
        for k, v in part.items():
            out.setdefault(k, set()).update(v)
        log(f"Xbox: {p} -> {len(part)} exe names")
    return (out, "Xbox KnownGameList") if out else (None, None)


def from_registry(args):
    part = loc.read_gameconfigstore()
    if not part:
        return None, None
    log(f"Registry GameConfigStore: {len(part)} exe names")
    return part, "Registry GameConfigStore"


# ---------- snapshots (change detection, CI without NVIDIA/Xbox) ----------
# sources/<name>.tsv: "exe<TAB>game1|game2", sorted. Written after every successful
# read; used instead of the live source when it is unavailable (e.g. on a CI server).

def snapshot_text(part: dict[str, set[str]]) -> str:
    rows = []
    for exe in sorted(part, key=str.lower):
        games = "|".join(sorted(g.replace("\t", " ").replace("|", "/") for g in part[exe]))
        rows.append(f"{exe}\t{games}" if games else exe)
    return "\n".join(rows) + "\n"


def snapshot_load(path: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        exe, _, games = line.partition("\t")
        out[exe] = set(filter(None, games.split("|")))
    return out


def use_source(name: str, live, args, c: "Collector", status: dict) -> str | None:
    """Adds a live source (and refreshes its snapshot) or falls back to the snapshot."""
    part, label = live
    snap = args.sources_dir / f"{name}.tsv" if args.sources_dir else None
    if part:
        if snap and (name != "registry" or args.snapshot_registry):
            text = snapshot_text(part)
            old = snap.read_text(encoding="utf-8") if snap.exists() else None
            status[name] = "unchanged" if old == text else ("new" if old is None else "changed")
            if old != text:
                snap.parent.mkdir(parents=True, exist_ok=True)
                snap.write_text(text, encoding="utf-8", newline="\n")
        else:
            status[name] = "live"
        c.add_map(part, name)
        return label
    if snap and snap.exists():
        part = snapshot_load(snap)
        c.add_map(part, name)
        status[name] = "snapshot"
        log(f"{name}: using snapshot {snap} ({len(part)} names)")
        return label  # same header text as a live read: no noise in git diffs
    return None


def from_rule_files(c: Collector, files: list[Path]) -> str | None:
    """Reads yaml (payload: - 'RULE') or text rule-providers."""
    done = []
    for f in files:
        n = 0
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line == "payload:":
                continue
            if line.startswith("- "):
                line = line[2:].strip()
                if len(line) >= 2 and line[0] == line[-1] and line[0] in "'\"":
                    q = line[0]
                    line = line[1:-1]
                    if q == "'":
                        line = line.replace("''", "'")
            line = line.split(" #", 1)[0].strip()
            if line.upper().startswith("PROCESS-NAME,"):
                c.add(loc.clean_name(line.split(",", 1)[1].strip()), "file", [f"file:{f.name}"])
            elif line:
                c.other_rules.setdefault(line, set()).add(f.name)
            n += 1
        log(f"File {f}: {n} rules")
        done.append(f.name)
    return "Files " + ", ".join(done) if done else None


# ---------- output ----------

def q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def main() -> int:
    ap = argparse.ArgumentParser(description="Discord + NVIDIA + Xbox -> one Mihomo rule-provider")
    ap.add_argument("-o", "--output", type=Path, default=Path("all_games.yaml"))
    ap.add_argument("--format", choices=["yaml", "text"], default="yaml")
    ap.add_argument("--no-discord", action="store_true")
    ap.add_argument("--no-nvidia", action="store_true")
    ap.add_argument("--nvidia-apps", action="store_true",
                    help="keep NVIDIA entries marked IsCreativeApplication (VLC, Blender ...)")
    ap.add_argument("--no-xbox", action="store_true")
    ap.add_argument("--no-registry", action="store_true")
    ap.add_argument("--discord-json", type=Path, help="saved detectable.json instead of download")
    ap.add_argument("--save-json", type=Path, help="save downloaded Discord JSON")
    ap.add_argument("--remote", action="store_true",
                    help="download NVIDIA fingerprint.db and Xbox KnownGameList from their servers "
                         "instead of reading local files (Xbox unpacking needs Windows)")
    ap.add_argument("--nvidia-url", help="fingerprint.db link (default: sources/nvidia_url.txt)")
    ap.add_argument("--kgl-rev", type=int, help="Xbox KGL revision to start probing from "
                                                 "(default: sources/xbox_rev.txt)")
    ap.add_argument("--fingerprint", type=Path, action="append", default=[])
    ap.add_argument("--known", type=Path, action="append", default=[])
    ap.add_argument("--rules-in", type=Path, action="append", default=[],
                    help="extra rule files to merge (yaml or text), e.g. steam_games.yaml")
    ap.add_argument("--extra", type=Path, action="append", default=[],
                    help="plain exe list, one per line")
    ap.add_argument("--deny", type=Path, action="append", default=[],
                    help="names to exclude, one per line")
    ap.add_argument("--keep-generic", action="store_true")
    ap.add_argument("--keep-apps", action="store_true",
                    help="keep non-game programs (OBS, Spotify, launchers ...)")
    ap.add_argument("--collapse-ue", action="store_true",
                    help="one regex for all *-Win64/Win32/WinGDK-Shipping.exe")
    ap.add_argument("--anticheat", action="store_true", help="add anti-cheat process rules")
    ap.add_argument("--path-rules", action="store_true",
                    help="add PROCESS-PATH-REGEX for Steam/Epic/Riot folders")
    ap.add_argument("--case-insensitive", action="store_true",
                    help="PROCESS-NAME-REGEX,(?i)^name$ instead of PROCESS-NAME")
    ap.add_argument("--sources-dir", type=Path,
                    help="keep per-source snapshots here (<name>.tsv); used for change "
                         "detection and as fallback when a source is unavailable")
    ap.add_argument("--snapshot-registry", action="store_true",
                    help="also snapshot the GameConfigStore registry (your own PC's games)")
    ap.add_argument("--only-if-changed", action="store_true",
                    help="with --sources-dir: do nothing if no source snapshot changed")
    ap.add_argument("--no-timestamp", action="store_true",
                    help="omit the 'Generated' line, so identical input gives an identical file")
    ap.add_argument("--text-output", type=Path,
                    help="also write the same rules in text format to this file")
    ap.add_argument("--comments", action="store_true",
                    help="(yaml) sources [D/N/X/R/F] and game names above each rule")
    args = ap.parse_args()

    log(f"Parser version: {loc.PARSER_VERSION} ({Path(loc.__file__).name})")
    c = Collector()
    sources = []
    status: dict[str, str] = {}
    labels = {"discord": "Discord detectable", "nvidia": "NVIDIA fingerprint.db",
              "xbox": "Xbox KnownGameList", "registry": "Registry GameConfigStore"}
    for name, enabled, fn in (("discord", not args.no_discord, from_discord),
                              ("nvidia", not args.no_nvidia, from_nvidia),
                              ("xbox", not args.no_xbox, from_xbox),
                              ("registry", not args.no_registry, from_registry)):
        if enabled:
            part, label = fn(args)
            sources.append(use_source(name, (part, label or labels[name]), args, c, status))
    if status:
        log("Sources: " + ", ".join(f"{k}={v}" for k, v in status.items()))
    if args.only_if_changed and args.output.exists() and status \
            and not any(v in ("changed", "new") for v in status.values()):
        log(f"No source changed since the last snapshot; {args.output} left as is.")
        return 0
    if args.rules_in:
        sources.append(from_rule_files(c, args.rules_in))
    for f in args.extra:
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                c.add(loc.basename(line), "file", [f"extra:{f.name}"])
    sources = [s for s in sources if s]
    total_raw = sum(c.counts.values())

    # Filtering
    deny = set()
    for f in args.deny:
        deny |= {l.split("#", 1)[0].strip().lower()
                 for l in f.read_text(encoding="utf-8").splitlines() if l.strip()}
    junk = lambda e: (not args.keep_generic) and (loc.is_junk(e) or e.lower() in dsc.DEFAULT_DENYLIST)
    if not args.keep_apps:
        deny |= NON_GAME_APPS
    items = {k: v for k, v in c.items.items() if k not in deny and not junk(v["name"])}
    log(f"Filtered out {len(c.items) - len(items)} generic / non-game / denied names")

    head_rules: list[tuple[str, str]] = []
    if args.collapse_ue:
        ue = re.compile(dsc.UE_SHIPPING_RE)
        n = len(items)
        items = {k: v for k, v in items.items() if not ue.search(k)}
        head_rules.append((f"Unreal Engine shipping builds ({n - len(items)} names)", dsc.UE_SHIPPING_RULE))
    if args.anticheat:
        ac = {a.lower() for a in dsc.ANTICHEAT_NAMES}
        items = {k: v for k, v in items.items() if k not in ac}
        head_rules += [("anti-cheat", dsc.make_rule(a, args.case_insensitive)) for a in dsc.ANTICHEAT_NAMES]
    if args.path_rules:
        head_rules += [("game library folder", r) for r in dsc.PATH_RULES]
    seen = {r for _, r in head_rules}
    for r, files in sorted(c.other_rules.items()):
        if r not in seen:
            head_rules.append((f"from {', '.join(sorted(files))}", r))
            seen.add(r)

    rules = list(head_rules)
    for k in sorted(items):
        it = items[k]
        tag = "".join(TAGS[s] for s in TAGS if s in it["src"])
        games = sorted(it["games"])
        g = ", ".join(games[:3]) + (f" (+{len(games) - 3})" if len(games) > 3 else "")
        rules.append((f"[{tag}] {g}".strip(), dsc.make_rule(it["name"], args.case_insensitive)))

    # Report
    by_src = {s: sum(1 for v in items.values() if s in v["src"]) for s in TAGS}
    only = {s: sum(1 for v in items.values() if v["src"] == {s}) for s in TAGS}
    log(f"Collected {total_raw} names from sources, {len(c.items)} unique, "
        f"{len(items)} after filters")
    for s in TAGS:
        if by_src[s]:
            log(f"  {s:9} {by_src[s]:6} names, {only[s]:6} only from this source")

    out = ["# Mihomo rule-provider (behavior: classical)"]
    out += [f"# Source: {s}" for s in sources]
    if not args.no_timestamp:
        out.append(f"# Generated: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}")
    out.append(f"# Rules: {len(rules)}")
    if args.comments:
        out.append("# Tags: D=Discord N=NVIDIA X=Xbox R=Registry F=File")
    if args.format == "yaml":
        out.append("payload:")
        for cm, r in rules:
            if args.comments:
                out.append(f"  # {cm.replace(chr(10), ' ')}")
            out.append(f"  - {q(r)}")
    else:
        out += [r for _, r in rules]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    if args.text_output and args.format == "yaml":
        txt = [l for l in out if l.startswith("# ") and not l.startswith("# Tags")] + [r for _, r in rules]
        args.text_output.parent.mkdir(parents=True, exist_ok=True)
        args.text_output.write_text("\n".join(txt) + "\n", encoding="utf-8", newline="\n")
        log(f"Wrote {len(rules)} rules to {args.text_output}")
    log(f"Wrote {len(rules)} rules to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
