# soc-ShinyHunters — Threat Actor Tracker

> Monitor the ShinyHunters actor across multiple feeds.

**Port:** `8097` &nbsp;|&nbsp; **Repo:** `diagonalciso/soc-shinyhunters` &nbsp;|&nbsp; **Service:** `soc-shinyhunters.service` &nbsp;|&nbsp; **Stack:** stdlib Python (no external deps)

Part of the **CD / Wazuh Full SOC** suite. Open the in-app **`?` Help button** (top-right of the dashboard) to read this manual, or view it here.

---

## 1. Overview

soc-ShinyHunters tracks the ShinyHunters threat actor across ransomware.live, OTX, MISP Galaxy and RSS sources, consolidating breach claims and activity into one view for the SOC.

## 2. Key features

- Consolidated ShinyHunters activity from several feeds
- OTX + MISP Galaxy + RSS enrichment
- Searchable event list
- Actor-focused situational awareness

## 3. Running the service

The service is a single self-contained `app.py` using only the Python standard library.

```bash
# systemd (fleet / suite install)
sudo systemctl status soc-shinyhunters
sudo systemctl restart soc-shinyhunters
sudo journalctl -u soc-shinyhunters -f

# manual run (from the repo directory)
cp .env.example .env      # then edit as needed
env $(grep -v '^#' .env | xargs) python3 app.py
```

Then open **http://<host>:8097/**.

## 4. Configuration (environment variables)

Set these in `.env` (see `.env.example` for defaults):

| Variable | Notes |
|---|---|
| `BF_SESSION` |  |
| `OTX_API_KEY` | Secret — keep out of git; set only in `.env`. |
| `PORT` | Listen port (default 8097). |

## 5. HTTP endpoints

| Path | |
|---|---|
| `/` | Main dashboard (HTML) |
| `/api/data` | API endpoint (JSON) |
| `/manual` | This manual (opened by the top-right **?** Help button) |

## 6. Integration

Complements soc-ransomware / soc-qilin; enrich in soc-intel.

## 7. Security & operational notes

For defensive tracking; verify claims before acting.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Page will not load | `systemctl status soc-shinyhunters`; confirm the port `8097` is listening (`lsof -i:8097`). |
| Help button shows "MANUAL.md not found" | Ensure `MANUAL.md` sits next to `app.py` in the service directory. |
| Service keeps restarting | `journalctl -u soc-shinyhunters -e` for the traceback; usually a missing `.env` value. |
| Empty / stale data | Confirm upstream sources and any API keys in `.env` are reachable. |

---

*Manual for soc-shinyhunters. Part of the CD / Wazuh Full SOC suite. Private © CisoDiagonal.*
