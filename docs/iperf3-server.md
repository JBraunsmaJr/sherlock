# Setting up the iperf3 server

Sherlock's speed test measures the link between your gaming PC and another
machine on your network. That isolates the extender from your ISP, so the
numbers mean something.

## Where to put it

Use a Linux machine that is **wired directly to your router or switch**, not
through the extender and not over Wi-Fi. Otherwise you're measuring that
machine's link too.

Check its own link first:

```sh
ip -br link                      # find the interface name, e.g. enp3s0
sudo ethtool enp3s0 | grep -E 'Speed|Duplex'
```

It should report `Speed: 1000Mb/s` (or more) and `Duplex: Full`. If the server
itself is at 100 Mb/s, every test will top out there.

## Option A: installed directly (systemd)

```sh
sudo apt install iperf3          # Debian/Ubuntu. Fedora: sudo dnf install iperf3
```

Debian may ask whether to start iperf3 as a daemon. Answer **No**; the unit
below gives you more control.

```sh
sudo tee /etc/systemd/system/iperf3.service >/dev/null <<'EOF'
[Unit]
Description=iperf3 server for Sherlock
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/iperf3 --server --port 5201
Restart=always
RestartSec=5
DynamicUser=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now iperf3
systemctl status iperf3 --no-pager
```

## Option B: Docker

Host networking avoids Docker's NAT layer, which can cost throughput and
skew results:

```sh
docker run -d --name iperf3 --restart unless-stopped \
  --network host networkstatic/iperf3 -s -p 5201
```

Or with Compose:

```yaml
services:
  iperf3:
    image: networkstatic/iperf3
    command: ["-s", "-p", "5201"]
    network_mode: host
    restart: unless-stopped
```

If you'd rather publish the port than use host networking, use
`-p 5201:5201` instead of `--network host`.

## Open the firewall

Only TCP 5201 is needed.

```sh
sudo ufw allow from 192.168.1.0/24 to any port 5201 proto tcp   # ufw; adjust to your LAN
# or, with firewalld:
sudo firewall-cmd --permanent --add-port=5201/tcp && sudo firewall-cmd --reload
```

There's no authentication on a plain iperf3 server, so keep it reachable from
your LAN only. Don't forward the port on your router.

## Install the client on Windows

The iperf3 project doesn't publish official Windows builds; use a community
build such as the one at <https://github.com/ar51an/iperf3-win-builds>. Put
`iperf3.exe` next to `sherlock.exe` (and set `"iperf3_path": "iperf3.exe"` in
the config) or somewhere on your `PATH`.

## Check it by hand first

From the Windows PC, through the extender:

```powershell
iperf3.exe -c 192.168.1.50          # upload: the PC sends
iperf3.exe -c 192.168.1.50 -R       # download: the server sends
```

On a healthy gigabit link expect about 940 Mbps each way. Roughly 94 Mbps
means something negotiated down to 100 Mbps, which is worth checking with
`sherlock interfaces`.

## Point Sherlock at it

In `sherlock.json`:

```json
"throughput": {
  "mode": "manual",
  "iperf3_path": "iperf3.exe",
  "server": "192.168.1.50",
  "port": 5201,
  "duration": "5s",
  "interval": "30m",
  "windows": [],
  "skip_processes": ["cs2.exe", "VALORANT-Win64-Shipping.exe"],
  "skip_above_mbps": 20
}
```

Restart Sherlock, then use **Run speed test** on the dashboard. Switch to
**Scheduled** once it works. Each test runs upload then download for the
configured duration, so a 5-second setting saturates the link for about ten
seconds.

## Troubleshooting

| Message | Fix |
|---|---|
| `unable to connect to server` | Firewall, wrong IP, or the service isn't running (`systemctl status iperf3`). |
| `the server is busy running a test` | iperf3 serves one test at a time. Something else is testing; it'll retry next interval. |
| `is iperf3 installed?` | Sherlock couldn't run `iperf3_path`. Use a full path, e.g. `C:\\Tools\\iperf3.exe`. |
| Results around 94 Mbps | A link in the path is running at 100 Mbps: the PC, the extender, or the server. |
