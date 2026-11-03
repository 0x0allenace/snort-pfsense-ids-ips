# Test Results

All results below are drawn directly from pfSense Alerts/Blocked-tab screenshots, not inferred. Test host: `wrk-price` (10.0.1.4, ECORP). Payload host: Kali Linux (10.0.3.6, Attack LAN). Test date observed in logs: 2026-10-25. ECORP's Blocking Mode is confirmed as **Inline IPS Mode**.

## IDS Mode (Alert Only)

| Test | SID | Trigger | Expected | Observed | Result |
|---|---|---|---|---|---|
| Outbound ICMP | 10000001 | `ping 8.8.8.8` from `wrk-price` | Alert per ICMP packet | 4+ alerts logged, each with SID `1:10000001`, source 10.0.1.4 → destination 8.8.8.8, message "Ping detected" | ✅ Pass |
| HTTP `.exe` URI | 1000002 | `wrk-price` requested `http://10.0.3.6/payload.exe` | Alert on `.exe` in URI | 1 alert logged, SID `1:1000002`, source 10.0.1.4:58438 → destination 10.0.3.6:80, message "HTTP URI contains .exe" | ✅ Pass |

## IPS Mode (Drop + Alert)

| Test | SID | Trigger | Expected | Observed | Result |
|---|---|---|---|---|---|
| PE / MZ magic number | 1000013 | `wrk-price` requested a file whose HTTP payload begins with the MZ header, served from 10.0.3.6:80 | Traffic blocked; event logged in Blocked tab | 1 entry in Blocked tab — `TCP 10.0.1.4 → 10.0.3.6:80`, SID `1:1000013`, Priority 1, Class "Attempted Administrator", message "IPS: HTTP content contains MZ signature - blocked" | ✅ **Pass — confirmed per-packet drop (Inline IPS Mode)** |
| Outbound ICMP (IPS) | 10000011 | *(not yet run)* | Traffic blocked after first packet; host or packets logged in Blocked tab | *(no screenshot evidence yet)* | ⏳ Not yet tested |
| HTTP `.exe` URI (IPS) | 1000012 | *(not yet run)* | Traffic blocked; event logged in Blocked tab | *(no screenshot evidence yet)* | ⏳ Not yet tested |

## Open Items

- **Test the remaining two IPS rules** (SID 10000011 ICMP, SID 1000012 `.exe` URI) the same way SID 1000013 was tested, and add their Blocked-tab evidence here. Since Inline IPS Mode is confirmed for ECORP, these should also produce true per-packet `drop` results once tested.

## Environment Notes

- All test traffic was generated from isolated lab VMs (Kali, `wrk-price`) inside the home-lab network described in [`../docs/architecture.md`](../docs/architecture.md).
- The test payload (`payload.exe`) was a non-weaponized `msfvenom` test artifact used solely to produce a valid file with the MZ header for rule-testing purposes — it was never executed outside the isolated lab network.
