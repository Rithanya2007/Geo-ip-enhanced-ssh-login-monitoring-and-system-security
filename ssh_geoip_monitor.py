#!/usr/bin/env python3
"""
GeoIP-Enhanced SSH Login Monitoring & System Alert
====================================================

Watches SSH authentication events (from /var/log/auth.log, /var/log/secure,
or journald), enriches each login attempt with GeoIP location data, and
raises alerts on suspicious patterns:

  - Login from a country never seen before for that user
  - "Impossible travel" (two logins too far apart geographically to be
    physically possible in the elapsed time)
  - Burst of failed login attempts (possible brute force)
  - Successful login immediately following a failed-attempt burst

Alerts can be sent via email (SMTP), a webhook (Slack/Discord/generic),
and/or written to a local alert log. All behavior is driven by config.yaml.

Usage:
    python3 ssh_geoip_monitor.py --config config.yaml --follow
    python3 ssh_geoip_monitor.py --config config.yaml --once
    python3 ssh_geoip_monitor.py --config config.yaml --journald --follow

Author: (you)
License: MIT
"""

import argparse
import json
import math
import os
import re
import smtplib
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Missing dependency 'pyyaml'. Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class LoginEvent:
    timestamp: datetime
    user: str
    ip: str
    success: bool
    method: str = "unknown"          # e.g. publickey, password
    raw_line: str = ""


@dataclass
class GeoInfo:
    ip: str
    country: str = "Unknown"
    country_code: str = "XX"
    region: str = ""
    city: str = ""
    lat: float = 0.0
    lon: float = 0.0
    isp: str = ""
    is_private: bool = False


# --------------------------------------------------------------------------
# Log parsing
# --------------------------------------------------------------------------

# Matches common OpenSSH sshd log lines, e.g.:
#   Accepted publickey for alice from 203.0.113.10 port 51514 ssh2
#   Failed password for root from 198.51.100.7 port 22 ssh2
#   Failed password for invalid user admin from 198.51.100.7 port 22 ssh2
SSHD_LINE_RE = re.compile(
    r"sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+"
    r"(?P<method>\S+)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+"
)

# Syslog-style timestamp at the start of /var/log/auth.log lines, e.g. "Jul 31 10:15:02 host ..."
SYSLOG_TS_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})")


def parse_line(line: str, year_hint: int) -> "LoginEvent | None":
    """Parse a single sshd log line into a LoginEvent, or return None."""
    m = SSHD_LINE_RE.search(line)
    if not m:
        return None

    ts_match = SYSLOG_TS_RE.match(line)
    if ts_match:
        try:
            ts = datetime.strptime(f"{year_hint} {ts_match.group('ts')}", "%Y %b %d %H:%M:%S")
            ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    return LoginEvent(
        timestamp=ts,
        user=m.group("user"),
        ip=m.group("ip"),
        success=(m.group("result") == "Accepted"),
        method=m.group("method"),
        raw_line=line.strip(),
    )


def tail_file(path: str, from_start: bool = False):
    """Generator that yields new lines appended to a file, like `tail -f`."""
    with open(path, "r", errors="replace") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(1.0)


def read_file_once(path: str):
    with open(path, "r", errors="replace") as f:
        for line in f:
            yield line


def journald_follow(unit: str = "ssh"):
    """Generator that yields lines from `journalctl -u <unit> -f`."""
    cmd = ["journalctl", "-u", unit, "-f", "-n", "0", "-o", "short-iso"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors="replace")
    for line in proc.stdout:
        yield line


def journald_once(unit: str = "ssh", since: str = "-1d"):
    cmd = ["journalctl", "-u", unit, "--since", since, "-o", "short-iso"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    for line in out.splitlines():
        yield line + "\n"


# --------------------------------------------------------------------------
# GeoIP lookup (with local caching)
# --------------------------------------------------------------------------

PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "::1", "fe80:")


def is_private_ip(ip: str) -> bool:
    if ip.startswith(PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


class GeoIPResolver:
    """
    Resolves IPs to location info. Uses ip-api.com's free JSON endpoint by
    default (no API key required, rate-limited to ~45 req/min). Results are
    cached to disk so repeat IPs don't re-query.
    """

    def __init__(self, cache_path: str, provider: str = "ip-api", timeout: int = 5):
        self.cache_path = Path(cache_path)
        self.provider = provider
        self.timeout = timeout
        self.cache = {}
        if self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text())
            except (json.JSONDecodeError, OSError):
                self.cache = {}

    def _save_cache(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self.cache))

    def lookup(self, ip: str) -> GeoInfo:
        if is_private_ip(ip):
            return GeoInfo(ip=ip, country="Private/LAN", country_code="LAN", is_private=True)

        if ip in self.cache:
            d = self.cache[ip]
            return GeoInfo(**d)

        info = self._query(ip)
        self.cache[ip] = info.__dict__
        self._save_cache()
        return info

    def _query(self, ip: str) -> GeoInfo:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return GeoInfo(
                    ip=ip,
                    country=data.get("country", "Unknown"),
                    country_code=data.get("countryCode", "XX"),
                    region=data.get("regionName", ""),
                    city=data.get("city", ""),
                    lat=data.get("lat", 0.0),
                    lon=data.get("lon", 0.0),
                    isp=data.get("isp", ""),
                )
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            pass
        return GeoInfo(ip=ip, country="Unknown", country_code="XX")


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


# --------------------------------------------------------------------------
# State tracking (per-user history, for "new country" and "impossible travel")
# --------------------------------------------------------------------------

class UserStateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                self.data = {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, default=str))

    def known_countries(self, user: str) -> set:
        return set(self.data.get(user, {}).get("countries", []))

    def last_success(self, user: str):
        rec = self.data.get(user, {}).get("last_success")
        return rec  # dict with ts/lat/lon/country or None

    def record_success(self, user: str, geo: GeoInfo, ts: datetime):
        rec = self.data.setdefault(user, {"countries": [], "last_success": None})
        if geo.country_code not in rec["countries"]:
            rec["countries"].append(geo.country_code)
        rec["last_success"] = {
            "ts": ts.isoformat(),
            "lat": geo.lat,
            "lon": geo.lon,
            "country": geo.country,
        }
        self.save()


# --------------------------------------------------------------------------
# Failed-attempt burst tracking (simple sliding window, in-memory)
# --------------------------------------------------------------------------

class BruteForceTracker:
    def __init__(self, window_seconds: int, threshold: int):
        self.window = window_seconds
        self.threshold = threshold
        self.attempts = {}  # key -> list[datetime]

    def register_failure(self, key: str, ts: datetime) -> int:
        bucket = self.attempts.setdefault(key, [])
        bucket.append(ts)
        cutoff = ts.timestamp() - self.window
        bucket[:] = [t for t in bucket if t.timestamp() >= cutoff]
        return len(bucket)

    def recent_failure_count(self, key: str) -> int:
        return len(self.attempts.get(key, []))

    def clear(self, key: str):
        self.attempts.pop(key, None)


# --------------------------------------------------------------------------
# Alerting
# --------------------------------------------------------------------------

@dataclass
class Alert:
    level: str      # "info", "warning", "critical"
    title: str
    message: str


class AlertDispatcher:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.log_path = Path(cfg.get("alert_log_file", "alerts.log"))

    def send(self, alert: Alert):
        self._log_to_file(alert)
        if self.cfg.get("console", True):
            print(f"[{alert.level.upper()}] {alert.title}: {alert.message}")
        email_cfg = self.cfg.get("email", {})
        if email_cfg.get("enabled"):
            self._send_email(alert, email_cfg)
        webhook_cfg = self.cfg.get("webhook", {})
        if webhook_cfg.get("enabled"):
            self._send_webhook(alert, webhook_cfg)

    def _log_to_file(self, alert: Alert):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": alert.level,
                "title": alert.title,
                "message": alert.message,
            }) + "\n")

    def _send_email(self, alert: Alert, cfg: dict):
        try:
            msg = MIMEText(alert.message)
            msg["Subject"] = f"[SSH-Monitor][{alert.level.upper()}] {alert.title}"
            msg["From"] = cfg["from_addr"]
            msg["To"] = ", ".join(cfg["to_addrs"])
            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 587), timeout=10) as s:
                if cfg.get("use_tls", True):
                    s.starttls()
                if cfg.get("smtp_user"):
                    s.login(cfg["smtp_user"], cfg["smtp_password"])
                s.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())
        except Exception as e:
            print(f"[alert-dispatch] email send failed: {e}", file=sys.stderr)

    def _send_webhook(self, alert: Alert, cfg: dict):
        try:
            style = cfg.get("style", "slack")  # slack, discord, generic
            if style == "discord":
                payload = {"content": f"**[{alert.level.upper()}] {alert.title}**\n{alert.message}"}
            elif style == "generic":
                payload = {"level": alert.level, "title": alert.title, "message": alert.message}
            else:  # slack-compatible
                payload = {"text": f"*[{alert.level.upper()}] {alert.title}*\n{alert.message}"}
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                cfg["url"], data=data, headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            print(f"[alert-dispatch] webhook send failed: {e}", file=sys.stderr)


# --------------------------------------------------------------------------
# Core engine
# --------------------------------------------------------------------------

class SSHMonitor:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.geo = GeoIPResolver(
            cache_path=cfg.get("geoip_cache_file", "state/geoip_cache.json"),
            provider=cfg.get("geoip_provider", "ip-api"),
        )
        self.state = UserStateStore(cfg.get("user_state_file", "state/user_state.json"))
        bf_cfg = cfg.get("brute_force", {})
        self.brute = BruteForceTracker(
            window_seconds=bf_cfg.get("window_seconds", 120),
            threshold=bf_cfg.get("threshold", 5),
        )
        self.dispatcher = AlertDispatcher(cfg.get("alerts", {}))
        self.impossible_travel_kmh = cfg.get("impossible_travel_speed_kmh", 900)  # ~commercial flight speed
        self.ignore_users = set(cfg.get("ignore_users", []))

    def handle_event(self, event: LoginEvent):
        if event.user in self.ignore_users:
            return

        geo = self.geo.lookup(event.ip)

        if not event.success:
            self._handle_failure(event, geo)
            return

        self._handle_success(event, geo)

    def _handle_failure(self, event: LoginEvent, geo: GeoInfo):
        key = f"{event.user}@{event.ip}"
        count = self.brute.register_failure(key, event.timestamp)
        threshold = self.cfg.get("brute_force", {}).get("threshold", 5)
        if count == threshold:  # fire once when crossing the threshold
            self.dispatcher.send(Alert(
                level="warning",
                title="Possible brute-force attempt",
                message=(
                    f"{count} failed login attempts for user '{event.user}' from {event.ip} "
                    f"({geo.city}, {geo.country}) within "
                    f"{self.cfg.get('brute_force', {}).get('window_seconds', 120)}s."
                ),
            ))

    def _handle_success(self, event: LoginEvent, geo: GeoInfo):
        user = event.user
        known = self.state.known_countries(user)
        is_new_country = (geo.country_code not in known) and not geo.is_private and len(known) > 0

        last = self.state.last_success(user)
        impossible_travel = False
        travel_detail = ""
        if last and not geo.is_private and last.get("lat") and last.get("lon"):
            last_ts = datetime.fromisoformat(last["ts"])
            elapsed_h = max((event.timestamp - last_ts).total_seconds() / 3600.0, 1e-6)
            dist_km = haversine_km(last["lat"], last["lon"], geo.lat, geo.lon)
            required_speed = dist_km / elapsed_h
            if dist_km > 100 and required_speed > self.impossible_travel_kmh:
                impossible_travel = True
                travel_detail = (
                    f"Previous login was from {last['country']} at {last_ts.isoformat()}. "
                    f"Distance ~{dist_km:.0f} km in {elapsed_h:.2f}h implies "
                    f"~{required_speed:.0f} km/h travel speed."
                )

        recent_failures = self.brute.recent_failure_count(f"{user}@{event.ip}")

        if impossible_travel:
            self.dispatcher.send(Alert(
                level="critical",
                title="Impossible travel detected",
                message=(
                    f"User '{user}' logged in from {event.ip} ({geo.city}, {geo.country}) "
                    f"but this is not physically consistent with their previous login location. "
                    f"{travel_detail}"
                ),
            ))
        elif is_new_country:
            self.dispatcher.send(Alert(
                level="warning",
                title="Login from new country",
                message=(
                    f"User '{user}' logged in from {event.ip} ({geo.city}, {geo.country}), "
                    f"a country not seen before for this account. Method: {event.method}."
                ),
            ))

        if recent_failures >= self.cfg.get("brute_force", {}).get("threshold", 5):
            self.dispatcher.send(Alert(
                level="critical",
                title="Successful login after failed-attempt burst",
                message=(
                    f"User '{user}' succeeded in logging in from {event.ip} ({geo.city}, {geo.country}) "
                    f"after {recent_failures} recent failed attempts from the same source. "
                    f"This may indicate a compromised credential."
                ),
            ))
            self.brute.clear(f"{user}@{event.ip}")

        self.state.record_success(user, geo, event.timestamp)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    ap.add_argument("--follow", action="store_true", help="Continuously watch for new events (like tail -f)")
    ap.add_argument("--once", action="store_true", help="Process existing log history once, then exit")
    ap.add_argument("--journald", action="store_true", help="Read from journald instead of a log file")
    ap.add_argument("--journald-unit", default="ssh", help="systemd unit name for sshd (default: ssh)")
    ap.add_argument("--since", default="-1d", help="journald --since value for --once mode (default: -1d)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    monitor = SSHMonitor(cfg)
    year_hint = datetime.now().year

    if args.journald:
        line_source = journald_follow(args.journald_unit) if args.follow else journald_once(args.journald_unit, args.since)
    else:
        log_path = cfg.get("log_file", "/var/log/auth.log")
        if args.follow:
            line_source = tail_file(log_path, from_start=args.once)
        else:
            line_source = read_file_once(log_path)

    for line in line_source:
        event = parse_line(line, year_hint)
        if event:
            monitor.handle_event(event)


if __name__ == "__main__":
    main()
