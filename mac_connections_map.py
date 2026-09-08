#!/usr/bin/env python3
"""
mac_connections_map.py
----------------------

Copyright (c) 2026 Michael Corley. All rights reserved.
Proprietary. See LICENSE.txt. Not open source.

List remote IPs this Mac is connected to, the owning process, and
geographic location. Print a table, save CSV, and draw a world map image
with latitude/longitude markers.

Designed for older Macs (Mac Mini 2014 / Intel macOS). Uses `lsof`, which
is built into macOS. Geolocation uses free public APIs (no key required).

Usage:
    python3 mac_connections_map.py
    sudo python3 mac_connections_map.py   # recommended: sees all processes

Optional installs (script still runs without them):
    pip3 install --user requests matplotlib pillow
"""


from __future__ import print_function

import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import OrderedDict

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError, HTTPError
except ImportError:  # Python 2 fallback, unlikely
    from urllib2 import Request, urlopen, URLError, HTTPError

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OUT_DIR = os.path.abspath(os.path.expanduser("~/Desktop/connection_map"))
CSV_PATH = os.path.join(OUT_DIR, "connections.csv")
MAP_PNG = os.path.join(OUT_DIR, "connections_map.png")
MAP_HTML = os.path.join(OUT_DIR, "connections_map.html")
CACHE_PATH = os.path.join(OUT_DIR, "geo_cache.json")

# ip-api.com: free, no key, 45 req/min, HTTP only. Batch up to 100.
IP_API_BATCH = "http://ip-api.com/batch?fields=status,message,query,country,regionName,city,lat,lon,isp,org,as"
# HTTPS fallback, no key, ~1000/day
IPAPI_CO = "https://ipapi.co/{ip}/json/"

WORLD_MAP_URLS = [
    # Equirectangular-ish natural-earth style maps
    "https://upload.wikimedia.org/wikipedia/commons/8/83/Equirectangular_projection_SW.jpg",
    "https://upload.wikimedia.org/wikipedia/commons/thumb/8/83/Equirectangular_projection_SW.jpg/2000px-Equirectangular_projection_SW.jpg",
]


def ensure_outdir():
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)


def load_cache():
    if os.path.isfile(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache):
    try:
        with open(CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print("Warning: could not save geo cache: %s" % e)


# ---------------------------------------------------------------------------
# Connection collection (macOS lsof)
# ---------------------------------------------------------------------------
LSOF_RE = re.compile(
    r"^(?P<cmd>\S+)\s+(?P<pid>\d+)\s+\S+\s+\S+\s+(?P<proto>IPv[46])\s+"
    r".*?\s+(?P<kind>TCP|UDP)\s+(?P<name>.+)$"
)


def is_private_or_local(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_lsof_name(name, kind):
    """
    Examples:
      192.168.1.2:54321->142.250.72.78:443 (ESTABLISHED)
      192.168.1.2:5353->224.0.0.251:5353
      *:443 (LISTEN)
      [::1]:8080->[::1]:12345 (ESTABLISHED)
    """
    name = name.strip()
    status = ""
    mstat = re.search(r"\(([^)]+)\)\s*$", name)
    if mstat:
        status = mstat.group(1)
        name = name[: mstat.start()].strip()

    remote_ip, remote_port, local_ip, local_port = "", "", "", ""

    if "->" in name:
        left, right = name.split("->", 1)
        local_ip, local_port = split_host_port(left)
        remote_ip, remote_port = split_host_port(right)
    else:
        local_ip, local_port = split_host_port(name)

    return {
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "status": status or kind,
    }


def split_host_port(s):
    s = s.strip()
    if s.startswith("["):
        # [ipv6]:port
        m = re.match(r"\[([^\]]+)\]:(\d+|\*)$", s)
        if m:
            return m.group(1), m.group(2)
        return s.strip("[]"), ""
    if s.count(":") == 1:
        host, port = s.rsplit(":", 1)
        return host, port
    # IPv6 without brackets sometimes appears as host:port with many colons
    if ":" in s:
        host, port = s.rsplit(":", 1)
        if port.isdigit() or port == "*":
            return host, port
    return s, ""


def collect_via_lsof():
    cmd = ["lsof", "-nP", "-iTCP", "-iUDP"]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate()
    except OSError as e:
        print("lsof failed: %s" % e)
        return []

    if isinstance(out, bytes):
        out = out.decode("utf-8", "replace")

    rows = []
    seen = set()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        command = parts[0]
        pid = parts[1]
        proto_family = parts[4] if len(parts) > 4 else ""
        kind = parts[7] if len(parts) > 7 else ""
        # NAME is the last field(s)
        # Typical: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        name = " ".join(parts[8:]) if len(parts) > 8 else parts[-1]
        parsed = parse_lsof_name(name, kind)
        rip = parsed["remote_ip"]
        if not rip or rip in ("*", ""):
            continue
        if is_private_or_local(rip):
            continue
        key = (command, pid, rip, parsed["remote_port"], parsed["status"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "process": command,
                "pid": pid,
                "proto": kind,
                "family": proto_family,
                "local": "%s:%s" % (parsed["local_ip"], parsed["local_port"]),
                "remote_ip": rip,
                "remote_port": parsed["remote_port"],
                "status": parsed["status"],
            }
        )
    return rows


def collect_via_psutil():
    try:
        import psutil
    except ImportError:
        return []
    rows = []
    names = {}
    for p in psutil.process_iter(["pid", "name"]):
        try:
            names[p.info["pid"]] = p.info["name"]
        except Exception:
            pass
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return []
    seen = set()
    for c in conns:
        if not c.raddr:
            continue
        rip = c.raddr.ip
        rport = str(c.raddr.port)
        if is_private_or_local(rip):
            continue
        proc = names.get(c.pid, "?")
        key = (proc, c.pid, rip, rport, c.status)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "process": proc,
                "pid": str(c.pid or ""),
                "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "family": "IPv4" if c.family == socket.AF_INET else "IPv6",
                "local": "%s:%s" % (c.laddr.ip, c.laddr.port) if c.laddr else "",
                "remote_ip": rip,
                "remote_port": rport,
                "status": c.status,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Geolocation
# ---------------------------------------------------------------------------
def http_json(url, data=None, timeout=20):
    headers = {"User-Agent": "mac-connections-map/1.0", "Accept": "application/json"}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
        req = Request(url, data=body, headers=headers)
    else:
        req = Request(url, headers=headers)
    resp = urlopen(req, timeout=timeout)
    raw = resp.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    return json.loads(raw)


def lookup_batch_ipapi(ips):
    results = {}
    # batches of 100
    ips = list(ips)
    for i in range(0, len(ips), 100):
        chunk = ips[i : i + 100]
        payload = [{"query": ip} for ip in chunk]
        try:
            data = http_json(IP_API_BATCH, data=payload)
        except Exception as e:
            print("ip-api.com batch failed (%s); falling back per-IP." % e)
            return results
        if isinstance(data, dict):
            data = [data]
        for item in data:
            ip = item.get("query")
            if not ip:
                continue
            if item.get("status") == "success":
                results[ip] = {
                    "country": item.get("country") or "",
                    "region": item.get("regionName") or "",
                    "city": item.get("city") or "",
                    "lat": item.get("lat"),
                    "lon": item.get("lon"),
                    "isp": item.get("isp") or item.get("org") or "",
                    "asn": item.get("as") or "",
                }
            else:
                results[ip] = {
                    "country": "",
                    "region": "",
                    "city": item.get("message") or "lookup failed",
                    "lat": None,
                    "lon": None,
                    "isp": "",
                    "asn": "",
                }
        if i + 100 < len(ips):
            time.sleep(1.2)
    return results


def lookup_ipapi_co(ip):
    try:
        item = http_json(IPAPI_CO.format(ip=ip))
    except Exception as e:
        return {
            "country": "",
            "region": "",
            "city": "lookup failed: %s" % e,
            "lat": None,
            "lon": None,
            "isp": "",
            "asn": "",
        }
    if item.get("error"):
        return {
            "country": "",
            "region": "",
            "city": item.get("reason") or "lookup failed",
            "lat": None,
            "lon": None,
            "isp": "",
            "asn": "",
        }
    return {
        "country": item.get("country_name") or "",
        "region": item.get("region") or "",
        "city": item.get("city") or "",
        "lat": item.get("latitude"),
        "lon": item.get("longitude"),
        "isp": item.get("org") or "",
        "asn": item.get("asn") or "",
    }


def geolocate(ips, cache):
    needed = [ip for ip in ips if ip not in cache]
    if needed:
        print("Looking up %d unique public IP(s)..." % len(needed))
        batch = lookup_batch_ipapi(needed)
        cache.update(batch)
        still = [ip for ip in needed if ip not in cache]
        for ip in still:
            cache[ip] = lookup_ipapi_co(ip)
            time.sleep(0.6)
        save_cache(cache)
    return cache


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------
def location_str(geo):
    parts = [geo.get("city") or "", geo.get("region") or "", geo.get("country") or ""]
    parts = [p for p in parts if p]
    return ", ".join(parts) if parts else "unknown"


def _term_width():
    try:
        return max(80, int(subprocess.check_output(["tput", "cols"]).decode().strip()))
    except Exception:
        return 120


def print_table(rows):
    """Print a fixed-column table to the terminal (stdout)."""
    headers = [
        "Process",
        "PID",
        "Proto",
        "Remote IP",
        "Port",
        "Status",
        "Location",
        "Latitude",
        "Longitude",
        "ISP",
    ]
    table = []
    for r in rows:
        g = r.get("geo") or {}
        lat = g.get("lat")
        lon = g.get("lon")
        table.append(
            [
                r["process"],
                r["pid"],
                r["proto"],
                r["remote_ip"],
                r["remote_port"],
                r["status"],
                location_str(g),
                "" if lat is None else "%.4f" % float(lat),
                "" if lon is None else "%.4f" % float(lon),
                g.get("isp") or "",
            ]
        )

    # Preferred widths; shrink ISP/Location if the terminal is narrow
    preferred = [16, 7, 5, 16, 5, 12, 28, 10, 11, 24]
    term_w = _term_width()
    # 3 chars of padding per column ( " | " )
    pad = 3 * (len(headers) + 1)
    usable = max(60, term_w - pad)
    total_pref = sum(preferred)
    widths = []
    for i, pref in enumerate(preferred):
        min_w = len(headers[i])
        # scale, but never below header length
        w = max(min_w, int(round(pref * usable / float(total_pref))))
        widths.append(w)
    # give leftover to Location then ISP
    leftover = usable - sum(widths)
    if leftover != 0:
        widths[6] = max(len(headers[6]), widths[6] + leftover)

    def clip(s, w):
        s = str(s).replace("\n", " ")
        if len(s) <= w:
            return s
        if w <= 1:
            return s[:w]
        return s[: w - 1] + "~"

    def line(row, fill=" "):
        cells = []
        for i, cell in enumerate(row):
            cells.append(clip(cell, widths[i]).ljust(widths[i], fill))
        return "| " + " | ".join(cells) + " |"

    rule = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    print("")
    print("Active public connections")
    print(rule)
    print(line(headers))
    print(rule)
    for row in table:
        print(line(row))
    print(rule)
    print("%d row(s). CSV and map files are also written to:" % len(table))
    print("  %s" % OUT_DIR)
    print("")


def write_csv(rows):
    with open(CSV_PATH, "w") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "process",
                "pid",
                "proto",
                "local",
                "remote_ip",
                "remote_port",
                "status",
                "city",
                "region",
                "country",
                "latitude",
                "longitude",
                "isp",
                "asn",
            ]
        )
        for r in rows:
            g = r.get("geo") or {}
            w.writerow(
                [
                    r["process"],
                    r["pid"],
                    r["proto"],
                    r["local"],
                    r["remote_ip"],
                    r["remote_port"],
                    r["status"],
                    g.get("city") or "",
                    g.get("region") or "",
                    g.get("country") or "",
                    g.get("lat") if g.get("lat") is not None else "",
                    g.get("lon") if g.get("lon") is not None else "",
                    g.get("isp") or "",
                    g.get("asn") or "",
                ]
            )


# ---------------------------------------------------------------------------
# Maps
# ---------------------------------------------------------------------------
def write_html_map(points):
    """Standalone Leaflet map. Open in Safari — no extra Python deps."""
    markers_js = []
    for p in points:
        lat, lon = p["lat"], p["lon"]
        if lat is None or lon is None:
            continue
        popup = (
            "%s (pid %s)<br>%s:%s<br>%s<br>lat %s, lon %s"
            % (
                _esc(p["process"]),
                _esc(p["pid"]),
                _esc(p["remote_ip"]),
                _esc(p["remote_port"]),
                _esc(p["location"]),
                lat,
                lon,
            )
        )
        markers_js.append(
            "L.marker([%s, %s]).addTo(map).bindPopup(%s);"
            % (lat, lon, json.dumps(popup))
        )
    if not markers_js:
        center = "20, 0"
        zoom = "2"
    else:
        center = "%s, %s" % (points[0]["lat"], points[0]["lon"])
        zoom = "3"
    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Active remote connections</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
  html, body, #map { height: 100%%; margin: 0; }
  .note { position: absolute; z-index: 1000; top: 10px; left: 60px;
          background: #fff; padding: 8px 12px; border-radius: 4px;
          font: 13px/1.4 -apple-system, sans-serif; box-shadow: 0 1px 4px rgba(0,0,0,.3); }
</style>
</head>
<body>
<div id="map"></div>
<div class="note">Remote IPs this Mac is connected to &mdash; click a pin for process / coords</div>
<script>
var map = L.map('map').setView([%s], %s);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 18,
  attribution: '&copy; OpenStreetMap'
}).addTo(map);
%s
</script>
</body>
</html>
""" % (
        center,
        zoom,
        "\n".join(markers_js),
    )
    with open(MAP_HTML, "w") as f:
        f.write(html)


def _esc(s):
    return "" if s is None else str(s)


def latlon_to_xy(lat, lon, width, height):
    """Equirectangular projection onto a full world image."""
    x = (float(lon) + 180.0) / 360.0 * width
    y = (90.0 - float(lat)) / 180.0 * height
    return x, y


# Hand-drawn equirectangular outline (72 columns).
# Lon -180..180 left-to-right, lat ~75N..55S top-to-bottom.
_WORLD_ASCII = [
    "          .  ..        :##                     :####:          .  .         ",
    "     .  :##########   :###:         .    .   :##################:           ",
    "      :##############: ###      .            :####################:         ",
    "     :###:  :#########: :        :###:      :######: :#############:        ",
    "    :###     :######:           :#####:    :####:      :############:       ",
    "   :##:       :####:             :###:    :###:         :#####  ####:       ",
    "   :#:         :##:               :#     :###:            :###   ##:        ",
    "    :           #:     .-- equator --.    :##:             :##              ",
    "    :          :#:                       :####:            :#               ",
    "    :#:       :##:                      :######:                            ",
    "     :##:    :###:                     :########:                           ",
    "      :###::#####                       :######:           :####:           ",
    "       :#######:                         :####:           :######:          ",
    "        :#####:                           :##:             :####:           ",
    "         :###:                                              :##:            ",
    "          :#:                                                                ",
    "           .                  .                           .                 ",
]


def print_ascii_map(points):
    """Print a coastline-style world map in the terminal and pin each IP."""
    base = [list(row.rstrip("\n")) for row in _WORLD_ASCII]
    rows = len(base)
    cols = max(len(row) for row in base)
    for row in base:
        while len(row) < cols:
            row.append(" ")

    # Drawing covers roughly 75N..55S, full -180..180 longitude.
    lat_top, lat_bot = 75.0, -55.0
    lon_left, lon_right = -180.0, 180.0

    tokens = [str(i) for i in range(1, 10)] + [chr(ord("A") + i) for i in range(26)]
    legend = []
    used = {}
    n = 0
    for p in points:
        if p.get("lat") is None or p.get("lon") is None:
            continue
        if n >= len(tokens):
            break
        lat = float(p["lat"])
        lon = float(p["lon"])
        c = int((lon - lon_left) / (lon_right - lon_left) * cols)
        r = int((lat_top - lat) / (lat_top - lat_bot) * rows)
        c = max(0, min(cols - 1, c))
        r = max(0, min(rows - 1, r))
        token = tokens[n]
        key = (r, c)
        if key in used:
            token_shown = used[key]
        else:
            base[r][c] = token
            used[key] = token
            token_shown = token
        legend.append(
            "  %s  %-16s  %8.4f, %9.4f  %-28s  %s"
            % (
                token_shown,
                p["remote_ip"],
                lat,
                lon,
                (p.get("location") or "unknown")[:28],
                p.get("process") or "",
            )
        )
        n += 1

    print("World map in terminal (coastline sketch, not a photo)")
    print("  left = Alaska / Pacific     center = Africa     right = Australia / Pacific")
    print("  pins 1-9 / A-Z mark each public IP")
    print("+" + "-" * cols + "+")
    for row in base:
        print("|" + "".join(row) + "|")
    print("+" + "-" * cols + "+")
    if legend:
        print("Pins:")
        print("   #  IP                Latitude   Longitude   Location                      Process")
        for row in legend:
            print(row)
    else:
        print("No public IPs had coordinates to plot.")
    print("")


def download_world_map(dest):
    last_err = None
    for url in WORLD_MAP_URLS:
        try:
            req = Request(url, headers={"User-Agent": "mac-connections-map/1.0"})
            resp = urlopen(req, timeout=30)
            data = resp.read()
            if len(data) < 10000:
                continue
            with open(dest, "wb") as f:
                f.write(data)
            return dest
        except Exception as e:
            last_err = e
    raise IOError("Could not download world map: %s" % last_err)


def draw_map_pillow(points, dest_png):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return False

    bg_path = os.path.join(OUT_DIR, "world_base.jpg")
    if not os.path.isfile(bg_path):
        print("Downloading world map background...")
        download_world_map(bg_path)

    img = Image.open(bg_path).convert("RGBA")
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    w, h = img.size
    try:
        font = ImageFont.truetype("/Library/Fonts/Arial.ttf", max(12, w // 90))
        font_sm = ImageFont.truetype("/Library/Fonts/Arial.ttf", max(10, w // 110))
    except Exception:
        font = ImageFont.load_default()
        font_sm = font

    # title bar
    draw.rectangle([0, 0, w, int(h * 0.06)], fill=(20, 24, 32, 210))
    draw.text(
        (12, 8),
        "Remote connections from this Mac  —  lat/lon of each public IP",
        fill=(255, 255, 255, 255),
        font=font,
    )

    used_labels = []
    for i, p in enumerate(points):
        if p["lat"] is None or p["lon"] is None:
            continue
        x, y = latlon_to_xy(p["lat"], p["lon"], w, h)
        r = max(6, w // 180)
        draw.ellipse([x - r, y - r, x + r, y + r], fill=(220, 40, 40, 220), outline=(255, 255, 255, 255))
        label = "%s  %s, %s" % (
            p["process"],
            ("%.2f" % float(p["lat"])),
            ("%.2f" % float(p["lon"])),
        )
        tx, ty = x + r + 4, y - 8
        # nudge if overlapping previous
        for ux, uy in used_labels:
            if abs(tx - ux) < 80 and abs(ty - uy) < 14:
                ty += 14
        used_labels.append((tx, ty))
        draw.text((tx + 1, ty + 1), label, fill=(0, 0, 0, 180), font=font_sm)
        draw.text((tx, ty), label, fill=(255, 240, 200, 255), font=font_sm)

    out = Image.alpha_composite(img, overlay).convert("RGB")
    out.save(dest_png, "PNG", quality=92)
    return True


def draw_map_matplotlib(points, dest_png):
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False

    lons, lats, labels = [], [], []
    for p in points:
        if p["lat"] is None or p["lon"] is None:
            continue
        lons.append(float(p["lon"]))
        lats.append(float(p["lat"]))
        labels.append("%s\n%s" % (p["process"], p["remote_ip"]))

    fig, ax = plt.subplots(figsize=(14, 7), dpi=120)
    ax.set_xlim(-180, 180)
    ax.set_ylim(-90, 90)
    ax.set_xlabel("Longitude")
    ax.set_ylabel("Latitude")
    ax.set_title("Remote IP locations (process + coordinates)")
    ax.axhline(0, color="#888", lw=0.5)
    ax.axvline(0, color="#888", lw=0.5)
    ax.grid(True, ls=":", alpha=0.4)
    # crude continents outline not available; plot as lon/lat scatter
    if lons:
        ax.scatter(lons, lats, s=80, c="#d62828", zorder=3, edgecolors="white")
        for x, y, lab in zip(lons, lats, labels):
            ax.annotate(lab, (x, y), textcoords="offset points", xytext=(6, 4), fontsize=7)
    fig.tight_layout()
    fig.savefig(dest_png)
    plt.close(fig)
    return True


def draw_map(points):
    if draw_map_pillow(points, MAP_PNG):
        return MAP_PNG
    if draw_map_matplotlib(points, MAP_PNG):
        return MAP_PNG
    print(
        "Note: install Pillow or matplotlib to get a PNG map:\n"
        "    pip3 install --user pillow matplotlib"
    )
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ensure_outdir()
    if os.geteuid() != 0:
        print(
            "Tip: run with sudo so every process name is visible:\n"
            "    sudo python3 %s\n" % os.path.abspath(__file__)
        )

    rows = collect_via_lsof()
    if not rows:
        print("lsof returned no public remotes; trying psutil...")
        rows = collect_via_psutil()

    if not rows:
        print("No established connections to public IP addresses were found.")
        print("Browsers and apps often use short-lived connections; try again while a page is loading.")
        return 0

    # unique IPs for lookup
    unique_ips = list(OrderedDict((r["remote_ip"], None) for r in rows).keys())
    cache = load_cache()
    cache = geolocate(unique_ips, cache)

    for r in rows:
        r["geo"] = cache.get(r["remote_ip"], {})

    print_table(rows)
    write_csv(rows)
    print("CSV saved: %s" % CSV_PATH)

    points = []
    seen_ip = set()
    for r in rows:
        ip = r["remote_ip"]
        if ip in seen_ip:
            continue
        seen_ip.add(ip)
        g = r.get("geo") or {}
        points.append(
            {
                "process": r["process"],
                "pid": r["pid"],
                "remote_ip": ip,
                "remote_port": r["remote_port"],
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "location": location_str(g),
            }
        )

    print_ascii_map(points)

    write_html_map(points)
    print("Interactive map: %s" % MAP_HTML)
    print("  open with:  open %s" % MAP_HTML)

    png = draw_map(points)
    if png:
        print("Map image: %s" % png)
        print("  open with:  open %s" % png)

    print("\nLatitude / longitude by unique IP:")
    print("-" * 72)
    for p in points:
        print(
            "  %-16s  lat=%-10s lon=%-10s  %s  [%s]"
            % (
                p["remote_ip"],
                "?" if p["lat"] is None else p["lat"],
                "?" if p["lon"] is None else p["lon"],
                p["location"],
                p["process"],
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
