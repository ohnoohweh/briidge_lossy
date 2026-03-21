# Clean Test Suite — NAT + 300ms delay + 5-frame guarantee

**What this suite guarantees**
- On-wire ptypes: **DATA=0x01**, **CONTROL=0x02** (original).
- NAT overlay: **PC1:40001 ↔ PC2:443** (single logical path in both directions).
- **300 ms one way** overlay delay between PCs.
- Overlay frames are **RX-logged before delivery** — so PCAP shows overlay immediately *before* the local deliver on the receiver.
- **Exactly 5 frames** per message: local send → overlay DATA → local receive → CONTROL (rx→tx) → CONTROL (tx→rx).

**Files**
- `src/obstacle_bridge/transfer.py` – deterministic CONTROL emission: receiver sends CONTROL on DATA; sender replies with CONTROL on CONTROL.
- `virtual_net.py` – NAT mapping, 300ms overlay delay, overlay RX-first PCAP logging, local app logging with global IPs.
- `scripts/run_udp_bidir_tests.py` – five scenarios, including two large and one concurrent case.

**Run**
```bash
python run_udp_bidir_tests.py
```
