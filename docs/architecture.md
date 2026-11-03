# Lab Architecture

## Topology

```text
                                ┌──────────────┐
                                │   Internet   │
                                └──────┬───────┘
                                       │
                                ┌──────┴───────┐
                                │  Home Router │
                                └──────┬───────┘
                                       │
                         ┌─────────────┴─────────────┐
                         │      Proxmox Host          │
                         │   pfSense VM (firewall)    │
                         │   WAN: 192.168.1.249       │
                         └──────────────┬──────────────┘
                   ┌───────────────────┼───────────────────┐
                   │ 10.0.3.1          │ 10.0.1.1          │ 10.0.2.1
                   ▼                   ▼                   ▼
          ┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
          │  Attack LAN  │   │       ECORP        │   │      All-Safe      │
          │ 10.0.3.0/24  │   │    10.0.1.0/24     │   │    10.0.2.0/24     │
          │              │   │  ◄── Snort sensor   │   │                    │
          │ Kali Linux   │   │  (interface: ECORP) │   │  Purple Elastic     │
          │ 10.0.3.6     │   │                      │   │  Server 10.0.2.4   │
          │              │   │  DC-1 10.0.1.5       │   │                    │
          │              │   │  wrk-price 10.0.1.4  │   │  Ubuntu Velociraptor│
          │              │   │  wrk-colby 10.0.1.2  │   │  10.0.2.8           │
          └──────────────┘   └──────────────────┘   └──────────────────┘
```

## Components

| Component | IP | Role | Notes |
|---|---|---|---|
| pfSense (on Proxmox) | WAN 192.168.1.249 | Firewall / IDS-IPS host | Snort package installed via Package Manager |
| Snort sensor | — | IDS/IPS engine | Bound to the **ECORP** interface for inbound/outbound visibility into that segment |
| Kali Linux | 10.0.3.6 (Attack LAN) | Attacker-side test host | Generated the test payload (`payload.exe`) and served it over HTTP |
| `wrk-price` | 10.0.1.4 (ECORP) | Victim/test host | Source of every test alert in this project (ping, `.exe` download) |
| `wrk-colby` | 10.0.1.2 (ECORP) | ECORP workstation | Not used directly in Snort testing |
| `DC-1` | 10.0.1.5 (ECORP) | Domain controller | Not used directly in Snort testing |
| Purple Elastic Server | 10.0.2.4 (All-Safe) | SIEM/monitoring stack | Separate lab module, not part of this Snort project |
| Ubuntu Velociraptor | 10.0.2.8 (All-Safe) | DFIR tooling | Separate lab module, not part of this Snort project |

## Why the ECORP Interface

Snort was bound to the ECORP interface rather than WAN so that both inbound and outbound traffic for that network segment could be inspected — this gives visibility into traffic leaving the segment (e.g. outbound ICMP from `wrk-price`) as well as traffic entering it (e.g. the `.exe` download from Kali's web server at `10.0.3.6`).

## Blocking Mode

pfSense's Snort Interfaces overview page (**Services → Snort → Snort Interfaces**) shows a **Blocking Mode** column per interface — this determines whether a `drop` rule actually blocks matching packets inline (Inline IPS Mode) or whether blocking instead relies on the separate Legacy Mode + Block Offenders mechanism, which blocks the whole offending host rather than just the matching traffic (see [`detection-rules.md`](detection-rules.md) for the full distinction).

> **Confirmed:** the ECORP interface is set to **Inline IPS Mode**. The SID 1000013 block event (see [`../results/test-results.md`](../results/test-results.md)) is therefore a true per-packet `drop` — Snort blocked only the matching HTTP response, not the whole host.

## Versions

| Item | Version |
|---|---|
| pfSense | _fill in_ |
| Snort package | _fill in_ |
| Ruleset | Custom rules only (`custom.rules` category) |

> Fill in the exact pfSense and Snort package versions used before publishing, for reproducibility.
