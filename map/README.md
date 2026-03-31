# Fenceline Deep Map

The deep map is a curated database of **known-good network behavior** for every major package manager. It documents exactly which domains, IPs, CDN providers, and ports each tool contacts during normal operation.

## Why This Exists

Supply chain attacks work because no one knows what "normal" looks like. If you don't know that `npm install` should only talk to Cloudflare IPs on port 443, you can't detect when a compromised package opens a connection to a mining pool on port 3333.

The deep map fixes this. It gives you a machine-readable baseline to build detection rules against.

This data powers the detection engine in `fenceline install --sandbox`. When a package install makes a network connection, the sandbox checks it against this map to determine if the destination is expected.

## How It's Built

Every entry is derived from **public data only**:

- **DNS lookups** (`dig`, `nslookup`) against authoritative nameservers
- **Certificate transparency logs** via [crt.sh](https://crt.sh) for domain validation
- **ASN/whois databases** (ARIN, RIPE, APNIC) for IP ownership verification
- **CDN published IP ranges** (Cloudflare, Fastly, GitHub, Google Cloud publish their ranges)
- **Open source package manager code** — reading the actual source to identify every endpoint

IPs are point-in-time snapshots (CDNs rotate addresses). The CDN provider, ASN, and IP range are the stable identifiers to build rules against.

## Key Findings

1. **The entire package ecosystem runs on 4 CDNs.** Cloudflare (npm, yarn), Fastly (PyPI, crates.io, RubyGems), GitHub/Azure (Homebrew, Composer), and Google Cloud (Go modules). That's it.

2. **No package manager should EVER upload data during install.** The only legitimate outbound traffic is HTTP GET/HEAD requests for metadata and downloads, plus User-Agent headers. Any POST/PUT during `install` is suspicious.

3. **All tools use port 443 exclusively.** Every modern package manager uses HTTPS only. Any connection on a port other than 443 during package installation is a red flag.

4. **Only Homebrew has telemetry.** Every other major package manager sends zero analytics. Homebrew's telemetry is opt-out: set `HOMEBREW_NO_ANALYTICS=1`.

## Directory Structure

```
map/
├── README.md           # This file
├── schema.yaml         # YAML schema for tool entries
├── tools/              # One file per package manager
│   ├── npm.yaml
│   ├── pip.yaml
│   ├── cargo.yaml
│   ├── yarn.yaml
│   ├── homebrew.yaml
│   ├── go-modules.yaml
│   ├── rubygems.yaml
│   └── composer.yaml
└── cdns/               # CDN IP range references
    ├── cloudflare.yaml
    ├── fastly.yaml
    ├── aws.yaml
    └── google-cloud.yaml
```

## How to Read the YAML Files

Each tool file contains:

| Field | Description |
|-------|-------------|
| `description` | What the tool is |
| `primary_domains` | Domains contacted during normal install, with IPs, CDN provider, and ASN |
| `port` | Expected port (always 443) |
| `uploads_during_install` | Whether the tool sends data upstream during install (always false) |
| `telemetry` | Analytics endpoints and opt-out mechanisms |
| `known_mirrors` | Official/community mirrors |
| `notes` | Important operational details |

IPs within `primary_domains` are point-in-time DNS resolutions. Match against CDN ranges (in `cdns/`) rather than individual IPs for durable firewall rules.

## How to Contribute

1. **Verify existing data** — Run `dig <domain>` and `whois <ip>` to confirm entries are current
2. **Add missing domains** — If you find a package manager contacting a domain not listed, open a PR with DNS proof
3. **Update IP ranges** — CDN ranges change; pull fresh copies from the published sources linked in each CDN file
4. **Add new tools** — Follow `schema.yaml` for the expected structure

All data must be verifiable from public sources. No proprietary scanning or traffic capture required.

## License

Apache 2.0 — see [LICENSE](../LICENSE) in the project root.
