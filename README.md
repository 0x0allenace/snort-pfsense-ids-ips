# Snort IDS/IPS Deployment on pfSense

**Detect • Block • Verify**

A home-lab project deploying Snort as an open-source IDS/IPS on pfSense, writing three custom detection rules, and validating each one end-to-end in both alert-only (IDS) and blocking (IPS) modes.

---

## Objectives

- Deploy Snort on pfSense and bind it to the internal (ECORP) network interface for full traffic visibility.
- Write custom Snort rules targeting a reconnaissance signal and two malware-delivery indicators.
- Validate each rule against live test traffic generated in an isolated lab environment.
- Demonstrate the IDS → IPS transition (alerting vs. active blocking) and document the operational trade-offs observed.

## Outcomes

- All three IDS (alert-only) rules fired correctly against their intended trigger traffic, confirmed directly from pfSense Alerts-tab screenshots (see [`results/test-results.md`](results/test-results.md)).
- Confirmed that a filename-based rule (`.exe` in URI) can be trivially evaded by renaming the file, and that a content-based rule (PE/MZ magic number) catches the same payload regardless of extension.
- Confirmed the first real IPS `drop` block: the PE/MZ-signature rule (SID 1000013) blocked and logged a matching HTTP response in pfSense's **Blocked** tab. The ICMP and `.exe`-URI IPS variants are written but not yet tested.
- Confirmed ECORP is running in **Inline IPS Mode** — the SID 1000013 block was a true per-packet `drop`, not a Legacy Mode + Block Offenders whole-host block.

---

## Lab Environment

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
                         └──────────────┬──────────────┘
                   ┌───────────────────┼───────────────────┐
                   │ 10.0.3.1          │ 10.0.1.1          │ 10.0.2.1
                   ▼                   ▼                   ▼
          ┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
          │  Attack LAN  │   │       ECORP        │   │      All-Safe      │
          │              │   │  ◄── Snort sensor   │   │                    │
          │ Kali Linux   │   │  wrk-price 10.0.1.4  │   │  (SIEM/DFIR stack, │
          │ 10.0.3.6     │   │  (test/victim host)  │   │   separate module) │
          └──────────────┘   └──────────────────┘   └──────────────────┘
```

Full topology, host list, and version details: [`docs/architecture.md`](docs/architecture.md)

---

## Detection Rules

Each detection has a paired IDS (alert) and IPS (drop) rule, each with its own SID.

| Detection | IDS SID | IPS SID | Detects | ATT&CK Technique | Status |
|---|---|---|---|---|---|
| Outbound ICMP | 10000001 | 10000011 | Outbound ping from `HOME_NET` to `EXTERNAL_NET` | T1016.001 — Internet Connection Discovery | ✅ IDS confirmed · ⏳ IPS untested |
| HTTP `.exe` URI | 1000002 | 1000012 | HTTP requests for a URI containing `.exe` | T1105 — Ingress Tool Transfer | ✅ IDS confirmed · ⏳ IPS untested |
| PE / MZ magic number | 1000003 | 1000013 | Executables disguised with a non-`.exe` extension | T1036 — Masquerading | ✅ **IPS confirmed blocked** |

> **Note:** IPS `drop` rules only block traffic when the interface is in **Inline IPS Mode**. pfSense's separate **Legacy Mode + Block Offenders** mechanism blocks the whole offending host at the firewall level instead of the specific matching traffic — see [`docs/detection-rules.md`](docs/detection-rules.md) for the distinction.

Full rule breakdowns and rationale: [`docs/detection-rules.md`](docs/detection-rules.md)
Syntax reference: [`docs/appendix-rule-syntax.md`](docs/appendix-rule-syntax.md)

---

## IDS → IPS

Each rule was first validated in **IDS mode** (alert-only), then a paired `drop`-action IPS variant was written with its own SID. So far, the PE/MZ-signature rule (SID 1000013) has been loaded and tested: requesting the matching payload resulted in one entry in pfSense's **Blocked** tab (`TCP 10.0.1.4 → 10.0.3.6:80`, "IPS: HTTP content contains MZ signature - blocked"), confirming the drop rule fired. The ICMP and `.exe`-URI IPS variants exist but haven't been tested yet.

**Confirmed: ECORP is set to Inline IPS Mode.** The SID 1000013 block was a true per-packet `drop` — Snort sat inline and blocked only the matching HTTP response, rather than the broader whole-host blocking that Legacy Mode + Block Offenders would produce (see [`docs/architecture.md`](docs/architecture.md#blocking-mode) for the distinction between the two mechanisms).

---

## Results

See the full test matrix in [`results/test-results.md`](results/test-results.md).

| Mode | Rules tested | Result |
|---|---|---|
| IDS (alert-only) | SID 10000001, 1000002, 1000003 | ✅ 10000001 and 1000002 confirmed via screenshot; 1000003 deployed, IPS variant tested directly |
| IPS (drop) | SID 1000013 | ✅ Confirmed blocked (Blocked-tab evidence) |
| IPS (drop) | SID 10000011, 1000012 | ⏳ Not yet tested |

---

## Limitations

- **SID 1000002** inspects HTTP (port 80) only and is blind to the same download over HTTPS.
- **SID 1000003** only matches server→client traffic on port 80 and inspects the first 2 bytes of the payload — packed, encoded, or archived payloads where the PE header isn't at byte 0 would not be caught.
- Two of the three IPS rules (ICMP, `.exe` URI) are written but not yet tested against live traffic. Since the interface is confirmed to be in Inline IPS Mode, a successful test of these should behave the same way as SID 1000013 (per-packet `drop`), but this hasn't been directly observed yet.
- Detection is signature-based; none of these rules would catch a zero-day delivery mechanism that doesn't match the defined patterns.

## Next Steps

- Test the two remaining IPS rules (SID 10000011 ICMP, SID 1000012 `.exe` URI) the same way SID 1000013 was validated, and record the Blocked-tab evidence.
- Add HTTPS/TLS-aware detection coverage (e.g. JA3/JA3S fingerprinting or a TLS-terminating proxy ahead of Snort).
- Scope the PE-detection rule with `flow:` and content offsets to reduce the chance of missing non-zero-offset payloads.
- Forward Snort alerts to a SIEM (e.g. Splunk, Elastic, or Wazuh) for centralized correlation — see my related [Email Conversation Integrity Detection](https://github.com/0x0allenace/email-conversation-integrity-detection) project, which already has a SIEM integration layer this could feed into.

---

## Project Structure

```text
snort-pfsense-ids-ips/
│
├── README.md
├── LICENSE
│
├── docs/
│   ├── architecture.md              # Lab topology, components, versions
│   ├── detection-rules.md           # Full rule breakdowns and rationale
│   └── appendix-rule-syntax.md      # Snort rule syntax quick reference
│
├── rules/
│   ├── ids/
│   │   ├── 10000001-icmp-outbound.rules
│   │   ├── 1000002-exe-uri.rules
│   │   └── 1000003-pe-magic-number.rules
│   └── ips/
│       ├── 10000011-icmp-outbound-block.rules
│       ├── 1000012-exe-uri-block.rules
│       └── 1000013-pe-magic-number-block.rules
│
├── results/
│   └── test-results.md              # IDS/IPS test matrix and findings
│
└── images/
    └── (screenshots referenced by docs)
```

---

## Disclaimer

This project was carried out entirely in an isolated home-lab virtual environment for defensive security skill-building. The test payload referenced in the detection-rules documentation was a non-weaponized `msfvenom` artifact used only to produce a valid file signature for rule testing, and it was never executed outside the isolated lab network.

---

## Author

**Allen Ace**
Home Lab · Blue Team / Detection Engineering

*Detect • Block • Verify*
