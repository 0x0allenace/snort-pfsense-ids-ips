# Appendix: Snort Rule Syntax Reference

## Rule Anatomy

Every Snort rule has two parts: a **header** and a set of **options**.

```text
action protocol source_ip source_port -> dest_ip dest_port (options)
```

## Header Fields

| Field | Example | Meaning |
|---|---|---|
| Action | `alert`, `log`, `pass`, `drop` | What Snort does when the rule matches |
| Protocol | `tcp`, `udp`, `icmp`, `ip` | Protocol to inspect |
| Source IP / Port | `$HOME_NET any` | Where the traffic originates |
| Direction | `->` | Traffic flow direction (source to destination) |
| Destination IP / Port | `$EXTERNAL_NET any` | Where the traffic is headed |

## Common Actions

| Action | Behavior |
|---|---|
| `alert` | Generate an alert and log the event |
| `log` | Log the traffic without alerting |
| `pass` | Ignore traffic matching the rule |
| `drop` | Block and log the traffic (IPS mode only) |

## Common Rule Options

| Option | Purpose |
|---|---|
| `msg:"..."` | Human-readable message shown in the alert log |
| `sid:N` | Unique Snort ID. Custom rules should start at 1,000,000 to avoid colliding with official ruleset IDs |
| `rev:N` | Rule revision number |
| `content:"..."` | Byte or string pattern to match in the packet/payload |
| `nocase` | Makes the preceding `content` match case-insensitive |
| `http_uri` | Restricts a `content` match to the HTTP URI field only |
| `file_data` | Restricts a `content` match to decoded file content within the payload |
| `depth:N` | Limits how many bytes from the start of the match buffer are searched |
| `flow:` | Constrains the rule to a specific traffic direction/state (e.g. `established,to_server`) |

## SID Numbering Convention

| Range | Use |
|---|---|
| 1 – 999,999 | Reserved for official Snort / Talos rules |
| 1,000,000+ | Local/custom rules |

> Always confirm a new SID isn't already in use elsewhere in `custom.rules` before adding it — a collision will cause one rule to silently shadow the other.
