#!/usr/bin/env python3
"""
ShinyHunters Threat Actor Monitor — port 8097.

Multi-source tracker aggregating:
  - ransomware.live (live victim feed)
  - OTX AlienVault (IOC pulses, requires OTX_API_KEY)
  - MISP Galaxy (threat actor profile + aliases)
  - RSS news feeds (BleepingComputer, Krebs, DataBreaches.net, SecurityWeek)
  - BreachForums scrape attempt (breachforums.hn — likely CF-blocked without session)

stdlib only: urllib, json, xml, threading, time, os
"""

import json
import os
import re
import time
import threading
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT       = int(os.environ.get("PORT", 8097))
OTX_KEY    = os.environ.get("OTX_API_KEY", "")

ACTOR_NAME    = "ShinyHunters"
ACTOR_ALIASES = {"shinyhunters", "shinySp1d3r", "shiny hunters", "shiny_hunters"}
ACTOR_SLUG    = "shinyhunters"

TTL_VICTIMS  = 300      # 5 min
TTL_OTX      = 1800     # 30 min
TTL_NEWS     = 900      # 15 min
TTL_PROFILE  = 86400    # 24 h
TTL_BF       = 3600     # 1 h

RSS_FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("DataBreaches.net",  "https://www.databreaches.net/feed/"),
    ("SecurityWeek",      "https://feeds.feedburner.com/securityweek"),
    ("The Record",        "https://therecord.media/feed"),
]

_lock = threading.Lock()
_state = {
    "victims":     {"ts": 0, "items": [], "error": None},
    "otx":         {"ts": 0, "items": [], "error": None},
    "news":        {"ts": 0, "items": [], "error": None},
    "profile":     {"ts": 0, "data":  {}, "error": None},
    "breachforums":{"ts": 0, "items": [], "error": None},
}


# ── helpers ──────────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict | None = None, timeout: int = 20) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; ShinyHuntersMonitor/1.0 security-research)",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _is_actor(text: str) -> bool:
    t = text.lower()
    return any(a in t for a in ACTOR_ALIASES)


def _ago(ts: float) -> str:
    s = int(time.time() - ts)
    if s < 60:   return f"{s}s ago"
    if s < 3600: return f"{s//60}m ago"
    if s < 86400:return f"{s//3600}h ago"
    return f"{s//86400}d ago"


# ── data fetchers ─────────────────────────────────────────────────────────────

def fetch_victims():
    try:
        raw = _http_get("https://api.ransomware.live/recentvictims", timeout=30)
        all_victims = json.loads(raw)
        watched = [
            v for v in all_victims
            if _is_actor(v.get("group_name", ""))
        ]
        with _lock:
            _state["victims"] = {"ts": time.time(), "items": watched, "error": None}
    except Exception as e:
        with _lock:
            _state["victims"]["error"] = str(e)


def fetch_otx():
    if not OTX_KEY:
        with _lock:
            _state["otx"] = {"ts": time.time(), "items": [], "error": "OTX_API_KEY not set"}
        return
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=25"
        raw = _http_get(url, headers={"X-OTX-API-KEY": OTX_KEY}, timeout=60)
        data = json.loads(raw)
        pulses = [p for p in data.get("results", []) if _is_actor(p.get("name","")) or _is_actor(p.get("description",""))]
        items = []
        for p in pulses:
            items.append({
                "id":          p.get("id", ""),
                "name":        p.get("name", ""),
                "created":     (p.get("created") or "")[:10],
                "modified":    (p.get("modified") or "")[:10],
                "description": (p.get("description") or "")[:200],
                "ioc_count":   p.get("indicators_count", 0),
                "tags":        p.get("tags", []),
                "url":         f"https://otx.alienvault.com/pulse/{p.get('id','')}",
            })
        with _lock:
            _state["otx"] = {"ts": time.time(), "items": items, "error": None}
    except Exception as e:
        with _lock:
            _state["otx"]["error"] = str(e)


def fetch_news():
    articles = []
    errors = []
    for source, feed_url in RSS_FEEDS:
        try:
            raw = _http_get(feed_url, timeout=15)
            root = ET.fromstring(raw)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            items = root.findall(".//item") or root.findall(".//atom:entry", ns)
            for item in items:
                title = (item.findtext("title") or item.findtext("atom:title", namespaces=ns) or "").strip()
                link  = (item.findtext("link")  or item.findtext("atom:link", namespaces=ns) or "").strip()
                pubdate = (item.findtext("pubDate") or item.findtext("atom:published", namespaces=ns) or "")[:20]
                summary = (item.findtext("description") or item.findtext("atom:summary", namespaces=ns) or "")
                # strip HTML tags from summary
                summary = re.sub(r"<[^>]+>", "", summary).strip()[:300]
                if _is_actor(title) or _is_actor(summary):
                    articles.append({
                        "source":  source,
                        "title":   title,
                        "url":     link,
                        "date":    pubdate,
                        "summary": summary,
                    })
        except Exception as e:
            errors.append(f"{source}: {e}")
    with _lock:
        _state["news"] = {
            "ts":    time.time(),
            "items": articles,
            "error": "; ".join(errors) if errors else None,
        }


def fetch_profile():
    try:
        url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
        raw = _http_get(url, timeout=30)
        galaxy = json.loads(raw)
        profile = {}
        for entry in galaxy.get("values", []):
            name = entry.get("value", "")
            if _is_actor(name):
                meta = entry.get("meta", {})
                profile = {
                    "name":        name,
                    "description": entry.get("description", ""),
                    "aliases":     meta.get("synonyms", []),
                    "country":     meta.get("country", ""),
                    "motivation":  meta.get("motivation", []),
                    "target_cat":  meta.get("target-category", []),
                    "refs":        meta.get("refs", [])[:8],
                    "cfr_type":    meta.get("cfr-type-of-incident", []),
                    "source":      "MISP Galaxy threat-actor cluster",
                }
                break
        with _lock:
            _state["profile"] = {"ts": time.time(), "data": profile, "error": None if profile else "Not found in MISP Galaxy"}
    except Exception as e:
        with _lock:
            _state["profile"]["error"] = str(e)


def fetch_breachforums():
    """
    Attempt to scrape BreachForums search for ShinyHunters threads.
    Almost certainly blocked by Cloudflare without a valid session cookie.
    Set BF_SESSION env var to 'cf_clearance=<value>; PHPSESSID=<value>' to authenticate.
    """
    bf_session = os.environ.get("BF_SESSION", "")
    headers = {}
    if bf_session:
        headers["Cookie"] = bf_session

    items = []
    error = None
    try:
        url = "https://breachforums.hn/search.php?action=do_search&keywords=shinyhunters&postthread=1&sortby=dateline&order=desc"
        raw = _http_get(url, headers=headers, timeout=20)
        html = raw.decode("utf-8", errors="replace")

        if "Just a moment" in html or "cf-browser-verification" in html:
            raise RuntimeError("Cloudflare challenge — set BF_SESSION env var with valid cookies")
        if "You need to be logged in" in html.lower() or "login" in html.lower()[:500]:
            raise RuntimeError("Login required — set BF_SESSION with PHPSESSID cookie")

        # Rudimentary scrape: look for thread links
        for m in re.finditer(r'<a[^>]+href="(Thread-[^"]+)"[^>]*>([^<]+)</a>', html):
            link, title = m.group(1), m.group(2).strip()
            if _is_actor(title) or _is_actor(link):
                items.append({
                    "title": title,
                    "url":   f"https://breachforums.hn/{link}",
                })
    except Exception as e:
        error = str(e)

    with _lock:
        _state["breachforums"] = {"ts": time.time(), "items": items[:20], "error": error}


# ── background refresh loop ───────────────────────────────────────────────────

def _refresh_loop():
    while True:
        now = time.time()
        with _lock:
            v_ts  = _state["victims"]["ts"]
            o_ts  = _state["otx"]["ts"]
            n_ts  = _state["news"]["ts"]
            p_ts  = _state["profile"]["ts"]
            bf_ts = _state["breachforums"]["ts"]

        if now - v_ts  > TTL_VICTIMS:  threading.Thread(target=fetch_victims,     daemon=True).start()
        if now - o_ts  > TTL_OTX:      threading.Thread(target=fetch_otx,         daemon=True).start()
        if now - n_ts  > TTL_NEWS:     threading.Thread(target=fetch_news,         daemon=True).start()
        if now - p_ts  > TTL_PROFILE:  threading.Thread(target=fetch_profile,      daemon=True).start()
        if now - bf_ts > TTL_BF:       threading.Thread(target=fetch_breachforums, daemon=True).start()

        time.sleep(60)


# ── HTML dashboard ────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Soc-Shinyhunters — ShinyHunters Monitor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',monospace;font-size:13px}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
header{background:#161b22;border-bottom:1px solid #30363d;padding:12px 20px;display:flex;align-items:center;gap:12px}
header h1{font-size:16px;color:#d29922;font-weight:700;letter-spacing:1px}
header .actor{font-size:11px;color:#8b949e}
.stats-bar{background:#161b22;border-bottom:1px solid #21262d;display:flex}
.stat{flex:1;padding:12px 16px;border-right:1px solid #21262d;text-align:center}
.stat:last-child{border-right:none}
.stat .val{font-size:22px;font-weight:700;color:#d29922}
.stat .lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.tabs{background:#161b22;border-bottom:1px solid #21262d;display:flex;padding:0 20px}
.tab{padding:10px 16px;cursor:pointer;color:#8b949e;border-bottom:2px solid transparent;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.tab.active{color:#d29922;border-bottom-color:#d29922}
.tab:hover{color:#e6edf3}
.panel{display:none;padding:20px}
.panel.active{display:block}
.loading{text-align:center;padding:40px;color:#8b949e}
.error{color:#f85149;font-size:11px;margin:8px 0;padding:6px 10px;background:#1c1010;border:1px solid #f8514933;border-radius:4px}
.warn{color:#d29922;font-size:11px;margin:8px 0;padding:6px 10px;background:#1c1800;border:1px solid #d2992233;border-radius:4px}
table{width:100%;border-collapse:collapse}
thead th{background:#161b22;color:#8b949e;padding:8px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid #21262d;position:sticky;top:0;z-index:10}
tbody tr{border-bottom:1px solid #21262d;transition:background .1s}
tbody tr:hover{background:#161b22}
tbody td{padding:8px 12px;vertical-align:top}
.badge{display:inline-block;background:#1c2128;border:1px solid #d29922;color:#d29922;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600}
.badge-blue{border-color:#58a6ff;color:#58a6ff}
.badge-red{border-color:#f85149;color:#f85149}
.company{font-weight:600;color:#e6edf3}
.dim{color:#8b949e;font-size:11px}
.tag{display:inline-block;background:#21262d;color:#8b949e;padding:1px 5px;border-radius:2px;font-size:10px;margin:1px 2px 1px 0}
.card{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:16px;margin-bottom:12px}
.card h3{font-size:11px;text-transform:uppercase;color:#d29922;letter-spacing:.8px;margin-bottom:8px}
.kv{display:flex;gap:8px;margin-bottom:5px;font-size:12px}
.kv .k{color:#8b949e;min-width:120px;flex-shrink:0}
.kv .v{color:#e6edf3}
.news-item{border-bottom:1px solid #21262d;padding:10px 0}
.news-item:last-child{border-bottom:none}
.news-title{font-weight:600;color:#e6edf3;margin-bottom:3px}
.news-meta{font-size:10px;color:#8b949e;margin-bottom:4px}
.news-sum{font-size:11px;color:#8b949e}
.status-ok{color:#3fb950}
.status-err{color:#f85149}
.status-warn{color:#d29922}
.refresh-note{font-size:10px;color:#8b949e;margin-top:8px}
</style>
</head>
<body>
<header>
  <h1>&#9888; Soc-Shinyhunters <span style="font-weight:400;opacity:.6;font-size:.6em">ShinyHunters Monitor</span></h1>
  <span class="actor">Threat Actor Tracking — Multi-Source Intelligence Dashboard</span>
</header>
<div class="stats-bar">
  <div class="stat"><div class="val" id="s-victims">—</div><div class="lbl">Live Victims</div></div>
  <div class="stat"><div class="val" id="s-otx">—</div><div class="lbl">OTX Pulses</div></div>
  <div class="stat"><div class="val" id="s-news">—</div><div class="lbl">News Hits</div></div>
  <div class="stat"><div class="val" id="s-bf">—</div><div class="lbl">BreachForum Posts</div></div>
  <div class="stat"><div class="val" id="s-sources">—</div><div class="lbl">Sources Up</div></div>
</div>
<div class="tabs">
  <div class="tab active" onclick="showTab('overview')">Overview</div>
  <div class="tab" onclick="showTab('victims')">Victims</div>
  <div class="tab" onclick="showTab('iocs')">IOCs / Pulses</div>
  <div class="tab" onclick="showTab('news')">News</div>
  <div class="tab" onclick="showTab('profile')">Actor Profile</div>
  <div class="tab" onclick="showTab('status')">Source Status</div>
</div>

<div id="panel-overview" class="panel active"><div class="loading">Loading...</div></div>
<div id="panel-victims"  class="panel"><div class="loading">Loading...</div></div>
<div id="panel-iocs"     class="panel"><div class="loading">Loading...</div></div>
<div id="panel-news"     class="panel"><div class="loading">Loading...</div></div>
<div id="panel-profile"  class="panel"><div class="loading">Loading...</div></div>
<div id="panel-status"   class="panel"><div class="loading">Loading...</div></div>

<script>
let D = {};

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function flag(c){if(!c||c.length!==2)return'🌐';return String.fromCodePoint(...[...c.toUpperCase()].map(x=>0x1F1E6-65+x.charCodeAt(0)));}
function ago(ts){if(!ts)return'—';const d=new Date(ts.replace(' ','T'));const s=Math.floor((Date.now()-d.getTime())/1000);if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}

function showTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  const tabs=['overview','victims','iocs','news','profile','status'];
  document.querySelectorAll('.tab')[tabs.indexOf(name)].classList.add('active');
  document.getElementById('panel-'+name).classList.add('active');
  render(name);
}

async function load(){
  try{
    const r=await fetch('/api/data');
    D=await r.json();
    updateStats();
    render('overview');
  }catch(e){
    document.getElementById('panel-overview').innerHTML='<div class="error">Load error: '+esc(e.message)+'</div>';
  }
}

function updateStats(){
  document.getElementById('s-victims').textContent=D.victims.items.length;
  document.getElementById('s-otx').textContent=D.otx.items.length;
  document.getElementById('s-news').textContent=D.news.items.length;
  document.getElementById('s-bf').textContent=D.breachforums.items.length;
  const up=[D.victims,D.otx,D.news,D.profile,D.breachforums].filter(s=>!s.error||s.items?.length||s.data?.name).length;
  document.getElementById('s-sources').textContent=up+'/5';
}

function render(tab){
  if(tab==='overview') renderOverview();
  else if(tab==='victims') renderVictims();
  else if(tab==='iocs') renderIOCs();
  else if(tab==='news') renderNews();
  else if(tab==='profile') renderProfile();
  else if(tab==='status') renderStatus();
}

function renderOverview(){
  const v=D.victims.items, n=D.news.items, o=D.otx.items;
  const recent=v.slice(0,5);
  const recentNews=n.slice(0,4);
  let html='<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:1200px">';

  html+='<div class="card"><h3>Recent Victims (ransomware.live)</h3>';
  if(!recent.length) html+='<div class="dim">None in recent feed</div>';
  else recent.forEach(v=>{
    html+=`<div style="margin-bottom:8px"><span class="company">${esc(v.post_title||v.website||'?')}</span>
    <span class="dim"> ${flag(v.country)} ${esc(v.country)}</span><br>
    <span class="dim">${ago(v.discovered||v.published)}</span></div>`;
  });
  if(v.length>5)html+=`<div class="dim" style="margin-top:6px">+${v.length-5} more — see Victims tab</div>`;
  html+='</div>';

  html+='<div class="card"><h3>Recent News Mentions</h3>';
  if(!recentNews.length) html+='<div class="dim">No recent mentions in monitored feeds</div>';
  else recentNews.forEach(a=>{
    html+=`<div style="margin-bottom:8px"><a href="${esc(a.url)}" target="_blank" class="news-title">${esc(a.title)}</a><br>
    <span class="dim">${esc(a.source)} · ${esc(a.date)}</span></div>`;
  });
  html+='</div>';

  html+='<div class="card"><h3>OTX Intelligence Pulses</h3>';
  if(D.otx.error&&!o.length) html+=`<div class="warn">${esc(D.otx.error)}</div>`;
  else if(!o.length) html+='<div class="dim">No pulses found</div>';
  else o.slice(0,4).forEach(p=>{
    html+=`<div style="margin-bottom:8px"><a href="${esc(p.url)}" target="_blank">${esc(p.name)}</a><br>
    <span class="dim">${p.ioc_count} IOCs · modified ${esc(p.modified)}</span></div>`;
  });
  html+='</div>';

  html+='<div class="card"><h3>Threat Actor Profile</h3>';
  const pr=D.profile.data;
  if(!pr||!pr.name) html+=`<div class="dim">${esc(D.profile.error||'Profile not loaded yet')}</div>`;
  else{
    html+=`<div class="kv"><span class="k">Aliases</span><span class="v">${(pr.aliases||[]).slice(0,5).map(a=>`<span class="tag">${esc(a)}</span>`).join('')}</span></div>`;
    if(pr.motivation?.length)html+=`<div class="kv"><span class="k">Motivation</span><span class="v">${pr.motivation.map(m=>`<span class="tag">${esc(m)}</span>`).join('')}</span></div>`;
    if(pr.target_cat?.length)html+=`<div class="kv"><span class="k">Target Categories</span><span class="v">${pr.target_cat.slice(0,4).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</span></div>`;
    html+=`<div class="dim" style="margin-top:8px">${esc((pr.description||'').slice(0,300))}</div>`;
  }
  html+='</div>';

  html+='</div>';
  document.getElementById('panel-overview').innerHTML=html;
}

function renderVictims(){
  const items=D.victims.items;
  let html='';
  if(D.victims.error)html+=`<div class="warn">Note: ${esc(D.victims.error)}</div>`;
  if(!items.length){document.getElementById('panel-victims').innerHTML=html+'<div class="loading">No victims in current feed.</div>';return;}
  const rows=items.map(v=>`<tr>
    <td class="company">${esc(v.post_title||v.website||'—')}</td>
    <td>${flag(v.country)} <span class="dim">${esc(v.country)}</span></td>
    <td><span class="badge">${esc(v.group_name)}</span></td>
    <td><span class="dim">${esc(v.activity||'—')}</span></td>
    <td><span class="dim">${ago(v.discovered||v.published)}</span></td>
    <td>${v.website?`<a href="https://${esc(v.website)}" target="_blank">&#127760;</a>`:''}</td>
  </tr>`).join('');
  html+=`<table><thead><tr><th>Company</th><th>Country</th><th>Group</th><th>Sector</th><th>Discovered</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  html+=`<p class="refresh-note">Source: ransomware.live · ${items.length} victims · refreshes every 5 min</p>`;
  document.getElementById('panel-victims').innerHTML=html;
}

function renderIOCs(){
  const items=D.otx.items;
  let html='';
  if(D.otx.error)html+=`<div class="${items.length?'warn':'error'}">${esc(D.otx.error)}</div>`;
  if(!items.length){document.getElementById('panel-iocs').innerHTML=html+'<div class="loading">No matching pulses in subscribed feed. OTX /search endpoint down — using subscribed feed fallback.</div>';return;}
  const rows=items.map(p=>`<tr>
    <td><a href="${esc(p.url)}" target="_blank">${esc(p.name)}</a><br><span class="dim">${esc(p.description)}</span></td>
    <td>${p.ioc_count}</td>
    <td>${esc(p.modified)}</td>
    <td>${p.tags.slice(0,5).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</td>
  </tr>`).join('');
  html+=`<table><thead><tr><th>Pulse</th><th>IOCs</th><th>Modified</th><th>Tags</th></tr></thead><tbody>${rows}</tbody></table>`;
  html+=`<p class="refresh-note">Source: AlienVault OTX search · refreshes every 30 min</p>`;
  document.getElementById('panel-iocs').innerHTML=html;
}

function renderNews(){
  const items=D.news.items;
  let html='';
  if(D.news.error)html+=`<div class="warn">Some feeds failed: ${esc(D.news.error)}</div>`;
  if(!items.length){document.getElementById('panel-news').innerHTML=html+'<div class="loading">No news mentions found in monitored RSS feeds.</div>';return;}
  items.forEach(a=>{
    html+=`<div class="news-item">
      <div class="news-title"><a href="${esc(a.url)}" target="_blank">${esc(a.title)}</a></div>
      <div class="news-meta"><span class="badge badge-blue">${esc(a.source)}</span> &nbsp; ${esc(a.date)}</div>
      ${a.summary?`<div class="news-sum">${esc(a.summary)}</div>`:''}
    </div>`;
  });
  html+=`<p class="refresh-note">Sources: ${__RSS_FEED_NAMES__} · refreshes every 15 min</p>`;
  document.getElementById('panel-news').innerHTML=html;
}

function renderProfile(){
  const pr=D.profile.data;
  let html='';
  if(D.profile.error&&!pr?.name)html+=`<div class="warn">${esc(D.profile.error)}</div>`;
  if(!pr||!pr.name){document.getElementById('panel-profile').innerHTML=html+'<div class="loading">Profile not loaded yet.</div>';return;}
  html+=`<div class="card"><h3>${esc(pr.name)} — Threat Actor Profile</h3>
    <div class="kv"><span class="k">Source</span><span class="v">${esc(pr.source)}</span></div>
    <div class="kv"><span class="k">Aliases</span><span class="v">${(pr.aliases||[]).map(a=>`<span class="tag">${esc(a)}</span>`).join('')||'—'}</span></div>
    ${pr.country?`<div class="kv"><span class="k">Country</span><span class="v">${esc(pr.country)}</span></div>`:''}
    ${pr.motivation?.length?`<div class="kv"><span class="k">Motivation</span><span class="v">${pr.motivation.map(m=>`<span class="tag">${esc(m)}</span>`).join('')}</span></div>`:''}
    ${pr.target_cat?.length?`<div class="kv"><span class="k">Target Categories</span><span class="v">${pr.target_cat.map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</span></div>`:''}
    ${pr.cfr_type?.length?`<div class="kv"><span class="k">Incident Type</span><span class="v">${pr.cfr_type.map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</span></div>`:''}
  </div>`;
  if(pr.description)html+=`<div class="card"><h3>Description</h3><p style="line-height:1.6;color:#e6edf3">${esc(pr.description)}</p></div>`;
  if(pr.refs?.length){
    html+=`<div class="card"><h3>References</h3>`;
    pr.refs.forEach(r=>{html+=`<div style="margin-bottom:4px"><a href="${esc(r)}" target="_blank">${esc(r)}</a></div>`;});
    html+='</div>';
  }
  document.getElementById('panel-profile').innerHTML=html;
}

function renderStatus(){
  const sources=[
    {name:'ransomware.live', key:'victims', label:'Live victim feed (5min TTL)'},
    {name:'AlienVault OTX',  key:'otx',     label:'Pulse search (30min TTL, needs OTX_API_KEY)'},
    {name:'RSS News Feeds',  key:'news',    label:'Security blog RSS (15min TTL)'},
    {name:'MISP Galaxy',     key:'profile', label:'Threat actor profile (24h TTL)'},
    {name:'BreachForums',    key:'breachforums', label:'Forum scrape (1h TTL, CF-protected)'},
  ];
  let html='<div style="max-width:700px">';
  sources.forEach(s=>{
    const st=D[s.key];
    const hasData=(st.items?.length||0)>0||(st.data&&Object.keys(st.data).length>0);
    const cls=st.error&&!hasData?'status-err':st.error?'status-warn':'status-ok';
    const icon=st.error&&!hasData?'&#10007;':st.error?'&#9888;':'&#10003;';
    html+=`<div class="card">
      <h3><span class="${cls}">${icon}</span> ${esc(s.name)}</h3>
      <div class="kv"><span class="k">Purpose</span><span class="v dim">${esc(s.label)}</span></div>
      ${st.ts?`<div class="kv"><span class="k">Last fetched</span><span class="v dim">${_ago(st.ts)}</span></div>`:''}
      ${hasData?`<div class="kv"><span class="k">Items</span><span class="v status-ok">${(st.items?.length||0)+(st.data?.name?1:0)}</span></div>`:''}
      ${st.error?`<div class="error">${esc(st.error)}</div>`:''}
    </div>`;
  });
  html+='</div>';
  document.getElementById('panel-status').innerHTML=html;
}

function _ago(ts){if(!ts)return'never';const s=Math.floor(Date.now()/1000-ts);if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';return Math.floor(s/3600)+'h ago';}

load();
setInterval(load, 60000);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {args[0]} {args[1]}")

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            feed_names = json.dumps(", ".join(n for n, _ in RSS_FEEDS))
            self._html(HTML.replace("__RSS_FEED_NAMES__", feed_names))
        elif path == "/api/data":
            with _lock:
                self._json(_state)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    print(f"ShinyHunters Monitor → http://0.0.0.0:{PORT}")
    print(f"OTX key: {'set' if OTX_KEY else 'NOT SET — OTX tab will be empty'}")
    print("Starting initial data fetch...")
    for fn in (fetch_victims, fetch_news, fetch_profile, fetch_otx, fetch_breachforums):
        threading.Thread(target=fn, daemon=True).start()
    threading.Thread(target=_refresh_loop, daemon=True).start()
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
