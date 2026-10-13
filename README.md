# games-ruleset

Rule-provider для Mihomo: имена exe игр из Discord, NVIDIA и Xbox Game Bar,
плюс античиты и правила по папкам Steam/Epic/Riot. Собирается автоматически
в GitHub Actions, компьютер для этого не нужен.

## Откуда берутся данные

| Источник | Что качается | Как узнаётся новая версия |
|---|---|---|
| Discord | `discord.com/api/v9/applications/detectable` | всегда актуально |
| NVIDIA | `wpc-download.gfe.nvidia.com/static/<hash>/fingerprint.db` | манифест `ops-gx.nvidia.com/v3/applications/ontology/ontology.json` (ссылка + sha256) |
| Xbox | `dlassets-ssl.xboxlive.com/public/content/kgl/Version/<N>/kgl.<N>.compressed` | перебор номеров после `sources/xbox_rev.txt` |

* Всё качается напрямую с серверов, без входа в аккаунты, на обычном Linux.
* Xbox-файл сжат Windows XPRESS (внутри JSON). Распаковка на чистом Python
  по спецификации MS-XCA, сверена с Windows на реальном файле.
* Из базы NVIDIA пропускаются программы (`IsCreativeApplication`: VLC, Blender, OBS…).
* `sources/*.tsv` — снимки источников (`имя.exe<TAB>игра1|игра2`). По ним видно,
  что изменилось (`git log -p sources/`), и они подставляются, если источник
  временно недоступен. `nvidia_url.txt` — последняя ссылка NVIDIA на тот же случай.
* Итоговый файл без даты внутри: те же данные дают тот же файл, пустых коммитов нет.

## Установка

1. Создайте репозиторий на GitHub и положите в него эти файлы.
2. **Settings → Actions → General → Workflow permissions → Read and write permissions**.
3. **Actions → Build games ruleset → Run workflow** для первой сборки.
   Дальше сборка запускается каждый день сама.

## Подключение в Mihomo

```yaml
find-process-mode: always

rule-providers:
  games:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/Meldoner/games-ruleset/main/ruleset/games.yaml
    # или через CDN: https://cdn.jsdelivr.net/gh/Meldoner/games-ruleset@main/ruleset/games.yaml
    path: ./ruleset/games.yaml
    interval: 86400
    # proxy: PROXY   # если raw.githubusercontent.com недоступен напрямую

rules:
  - RULE-SET,games,PROXY
```

Текстовый вариант: `ruleset/games.txt` (`format: text`).

## Ручной запуск

```
python all_games_to_mihomo.py --remote --collapse-ue --anticheat --comments
```

Без `--remote` NVIDIA и Xbox читаются с этого ПК. Другие опции:
`--sources-dir sources`, `--only-if-changed`, `--no-timestamp`, `--text-output`,
`--deny file.txt`, `--keep-apps`, `--nvidia-apps`, `--rules-in steam_games.yaml`.
Проверка серверных источников: `python remote_sources.py`.
Сверка распаковки Xbox с Windows (на Windows): `python remote_sources.py --selftest`.
