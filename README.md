# GeoIP-Enhanced SSH Login Monitoring & System Alert

A lightweight Python tool that watches SSH authentication activity, enriches
each login attempt with GeoIP location data, and raises alerts on
suspicious patterns — without needing a full SIEM stack.

## Features

- **Parses SSH login events** from `/var/log/auth.log`, `/var/log/secure`,
  or `journald` (systemd-based distros)
- **GeoIP enrichment** for every login attempt (country, region, city, ISP)
  using the free [ip-api.com](https://ip-api.com) endpoint, with local
  disk caching to minimize lookups
- **Detects:**
  - Logins from a country never seen before for that user
  - "Impossible travel" — two successful logins geographically too far
    apart to be physically possible in the elapsed time
  - Brute-force / credential-stuffing bursts of failed attempts
  - A successful login immediately following a failed-attempt burst
    (possible compromised credential)
- **Alerting** via console, a local JSON alert log, email (SMTP), and/or a
  Slack/Discord/generic webhook — any combination, configured in one file
- No external services or paid API keys required to get started

## Requirements

- Python 3.8+
- Read access to the SSH log source (`/var/log/auth.log`/`/var/log/secure`,
  or `journalctl` access)
- Outbound internet access for GeoIP lookups (unless you swap in a local
  MaxMind GeoLite2 database — see [Notes](#notes))

## Installation

```bash
git clone https://github.com/<your-username>/geoip-ssh-monitor.git
cd geoip-ssh-monitor
pip install -r requirements.txt
cp config.yaml.example config.yaml   # if you keep an example separately
```

Edit `config.yaml` to point at your log source and enable the alert
channels you want (email and/or webhook).

## Usage

Process existing log history once and exit:

```bash
python3 ssh_geoip_monitor.py --config config.yaml --once
```

Continuously watch for new logins (like `tail -f`):

```bash
python3 ssh_geoip_monitor.py --config config.yaml --follow
```

Use `journald` instead of a log file (e.g. on distros where auth logs
aren't written to a plain file):

```bash
python3 ssh_geoip_monitor.py --config config.yaml --journald --journald-unit ssh --follow
```

## Running as a service

A sample `systemd` unit is included in `ssh-geoip-monitor.service`:

```bash
sudo cp -r . /opt/geoip-ssh-monitor
sudo cp ssh-geoip-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-geoip-monitor
sudo journalctl -u ssh-geoip-monitor -f
```

## Configuration reference

See the comments in `config.yaml` for every option. Key sections:

| Section | Purpose |
|---|---|
| `log_file` | Path to the sshd auth log (ignored with `--journald`) |
| `ignore_users` | Accounts to exclude from monitoring/alerting |
| `impossible_travel_speed_kmh` | Speed threshold (km/h) that flags impossible travel |
| `brute_force` | Sliding window + threshold for failed-attempt detection |
| `alerts.email` | SMTP settings for email alerts |
| `alerts.webhook` | Slack/Discord/generic webhook settings |

## State files

Runtime state is written under `state/` (gitignored by default):

- `state/geoip_cache.json` — cached IP → location lookups
- `state/user_state.json` — per-user known countries + last login location
- `state/alerts.log` — newline-delimited JSON record of every alert fired

## Security notes

- Store SMTP/webhook credentials outside version control (environment
  variables or a secrets manager), not committed directly in `config.yaml`.
- This tool detects and alerts; it does not block or rate-limit
  connections. Pair it with `fail2ban` or equivalent if you want automatic
  blocking of brute-force sources.
- GeoIP data (including free providers) can be imprecise, especially for
  VPNs, CGNAT, and mobile carriers — treat alerts as leads to investigate,
  not definitive proof of compromise.

## Notes

The GeoIP resolver currently uses the free `ip-api.com` JSON API (no key
required, rate-limited to ~45 requests/minute). To use a local MaxMind
GeoLite2 database instead (useful for high-volume or offline environments),
swap the `GeoIPResolver._query` method for a `geoip2.database.Reader`
lookup — the rest of the pipeline (caching, alerting, state tracking)
doesn't need to change.

## License

MIT
