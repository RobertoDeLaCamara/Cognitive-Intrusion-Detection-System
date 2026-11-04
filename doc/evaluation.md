# Measuring detection coverage

CNDS has no published recall figure yet. This page explains how to measure one with
`scripts/pcap_replay.py`, what the measurement does and does not cover, and what the
synthetic suite shows today.

## What the replay does

`pcap_replay.py` reads a PCAP and runs it through the same feature extractors and engines as
the live detector, then compares the verdicts with ground truth:

- Flows are scored as they time out, using the **packets' capture times** (not the wall clock),
  so durations, rates and inter-arrival times are real.
- Payload-pattern hits belong to their own flow, as in the live pipeline.
- The report gives **recall per attack class**, the **false-positive rate on benign flows**,
  the rules that fired, and a sweep over the ensemble threshold (0.5 / 0.65 / 0.8).

Not covered:

- **Threat-intel** boosts, per-`(src_ip, attack_type)` dedup and suppression rules are not simulated.
- The **baseline engine** is used when `MLFLOW_TRACKING_URI` points at the MLflow that holds the live-trained
  model; without it the scorer redistributes its weight and scores are not comparable with a deployment that has it.
- Only the engines whose model files are present are used; the report lists them. The
  Isolation Forest and LSTM in the repo are demo models, and `models/unified/` (FT-Transformer)
  is gitignored, so a fresh checkout replays with the rules and the bundled RF-lite model only.
- Flow-level scoring: an attack is "detected" when at least one of its flows is flagged, per
  flow, not per campaign.

## Ground truth

Two CSV formats (use either or both):

| Option | Columns | Use for |
|---|---|---|
| `--labels` | `src_ip,dst_ip,src_port,dst_port,protocol,label` | datasets with per-flow labels (either direction matches) |
| `--attacks` | `label,src_ip,dst_ip,dst_port,start,end` | datasets documented as "attacker X, from time A to B". Blank fields match anything. `start`/`end` are epoch seconds or `+N` seconds after the first packet |

A flow is attack traffic when the attacker is its initiator and it starts inside the window.
Everything unmatched is `BENIGN`.

```bash
python scripts/pcap_replay.py capture.pcap --attacks attacks.csv \
    --output results.json --report report.md
```

## 1. Synthetic suite (coverage smoke test)

```bash
python scripts/make_labelled_pcap.py --out /tmp/synth.pcap --attacks /tmp/synth_attacks.csv
python scripts/pcap_replay.py /tmp/synth.pcap --attacks /tmp/synth_attacks.csv --report /tmp/report.md
```

It builds 10 minutes of benign web/DNS traffic and six scripted attacks from one host: port
scan, SYN flood, SQL injection, XSS, SSH brute force and a DNS query burst. The traffic is
written by the same people who wrote the rules, so this tells you whether the **textbook
signatures are recognised end to end**. It is **not** a recall estimate for real attacks.

Result on a fresh checkout (rules + RF-lite, threshold 0.55; 389 benign flows):

| Class | Flows | Detected | Fired |
|---|---|---|---|
| sql_injection | 1 | 1 | `payload:sql_injection` |
| xss | 1 | 1 | `payload:xss` |
| syn_flood | 1 | 1 | `syn_scan` |
| port_scan | 200 | 0 | none |
| ssh_bruteforce | 40 | 0 | none |
| dns_burst | 300 | 0 | none |

False-positive rate on the benign background: 0 of 389. Reading the table:

- The signature-based classes (payload patterns, `syn_scan`) are caught because those rules are in
  `CRITICAL_RULES`.
- **Behavioural attacks are not caught by the rules alone.** A port scan is 200 two-packet flows,
  each unremarkable by itself; SSH brute force and a DNS burst have no rule. Catching them
  depends on the host-level engines (Isolation Forest, LSTM, baseline), which this replay
  does not run on a fresh checkout. Run it again with `models/` populated before drawing conclusions.
- **Full production engines (measured on the Raspberry Pi deployment).** Replaying the same suite in the
  detector image on the Pi (models mounted read-only, the deployment's own `.env`, threshold 0.65, baseline
  model v28 loaded from MLflow) gives: sql_injection, xss and syn_flood detected; **port_scan (200 flows),
  ssh_bruteforce (40) and dns_burst (300) not detected**; 0 of 389 benign flows flagged. The per-engine
  tables explain it. The baseline and the LSTM do react (mean 0.95-1.00 on those three classes, against
  0.83 and 0.71 on benign), but with the production weights (baseline 0.35, LSTM 0) their signal reaches at most
  about 0.45 once the supervised model votes "Benign" (score 0.00), well under the 0.65 threshold.
  The ablation confirms that dropping any engine other than the supervised one changes nothing.
  Caveat: the baseline was trained on the Pi's real network, so the synthetic benign hosts are unfamiliar to
  it (0.83 on average) and its separation here is small; the suite cannot tell a missing capability from an
  out-of-distribution test set. Use a capture from the deployment's own LAN for the false-positive side.
- `syn_flood` was detected in the replay but not by the live detector on the Raspberry Pi 5. The cause was
  Ethernet frame padding counted as TCP payload (a bare SYN is padded to 60 bytes), so `fwd_act_data_pkts`
  was 40 instead of 0 and `syn_scan` never fired on a real capture. Fixed in `FlowRecord` (`_l4_payload`); a
  pcap taken from a real NIC carries the same padding, a synthetic one does not, which is one more reason to
  validate on a capture you did not write.

## 2. A capture you did not write (the number worth quoting)

For a recall figure, replay labelled traffic that neither the rules nor the models were built
from:

1. Use a public capture that documents its attackers and time windows (check the dataset's own
   description for the attacker IPs and times, and its licence). The supervised model was trained on
   UNSW-NB15 and CIC-IDS2017 features, so **do not evaluate on the same data it trained on**: that
   measures memorisation.
2. Or record your own: capture the lab network with `tcpdump` while `cnds-red-team` (allowlisted
   targets, packet budget, kill switch) runs known scenarios, and write the `--attacks` file from its
   run log (`~/.cnds-red-team/runs.jsonl` has the exact windows).
3. Run the replay with the full model set (`models/` populated, same `.env` weights as production)
   and keep the JSON, the report and the CNDS commit hash together.

Report recall per class, the false-positive rate, and the engines that were available. A single
aggregate number hides which attacks are missed.

## Caveats

- Replay uses the engines' scores at the end of each flow; the live detector also dedups per
  `(src_ip, attack_type)` and applies suppression rules, which are not simulated.
- The Isolation Forest and LSTM see host features at the flow's expiry time, computed from the
  PCAP's own clock. Captures shorter than the host window (`HOST_WINDOW_SIZE`) give weaker host features.
- Class labels are free text; the report groups by the `label` you provide.
