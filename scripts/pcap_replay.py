#!/usr/bin/env python3
"""PCAP replay and detection-coverage measurement.

Replays .pcap files through the same feature extractors and engines as the live
detector, using the packets' own capture times, and (with ground truth) reports
recall per attack class, the false-positive rate on benign flows, which rules fired,
and a sweep over the ensemble threshold.

Ground truth, either or both:
  --labels   CSV, one row per flow: src_ip,dst_ip,src_port,dst_port,protocol,label
             (either direction of the flow matches)
  --attacks  CSV, one row per attack: label,src_ip,dst_ip,dst_port,start,end
             Blank dst_ip / dst_port / start / end match anything. start/end are epoch
             seconds, or "+N" seconds after the first packet of the pcap. A flow is
             attack traffic when the attacker is the flow's initiator (its first packet's
             source) and the flow starts inside the window. Everything unmatched is BENIGN.

The baseline engine is used when MLFLOW_TRACKING_URI points at the MLflow holding the
live-trained model (it is then the same model the detector serves). Not covered: threat-intel
boosts, dedup and suppression. The IF/LSTM files shipped in the repo are demo models, so the
report lists which engines were actually available.

Usage:
    python scripts/pcap_replay.py capture.pcap --attacks attacks.csv --report report.md
    python scripts/pcap_replay.py data/test.pcap --labels data/labels.csv --output results.json
"""

import argparse
import csv
import json
import logging
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scapy.all import PcapReader, IP

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.flow_extractor import FlowExtractor
from src.features.host_extractor import HostExtractor
from src.features.payload_analyzer import analyze_payload, extract_payload_features
from src.labels import is_benign
from src.engines.registry import supervised, iforest, lstm, baseline, rules, ensemble
from src.ensemble.scorer import EngineScores

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BENIGN = "BENIGN"
ENGINE_FIELDS = ("supervised", "isolation_forest", "lstm", "baseline", "rules")
SWEEP = (0.5, 0.65, 0.8)
EXPIRE_EVERY_S = 10.0  # how often (capture time) timed-out flows are collected


# ── ground truth ───────────────────────────────────────────────────────────

@dataclass
class AttackRule:
    label: str
    src_ip: str
    dst_ip: str = ""
    dst_port: Optional[int] = None
    start: Optional[str] = None  # epoch seconds or "+N"
    end: Optional[str] = None

    def window(self, t0: float) -> Tuple[float, float]:
        def conv(v, default):
            if v in (None, ""):
                return default
            v = str(v).strip()
            return t0 + float(v[1:]) if v.startswith("+") else float(v)
        return conv(self.start, float("-inf")), conv(self.end, float("inf"))

    def matches(self, key, start_time: float, t0: float) -> bool:
        src, dst, dport = key[0], key[1], key[3]
        if src != self.src_ip:
            return False
        if self.dst_ip and dst != self.dst_ip:
            return False
        if self.dst_port is not None and dport != self.dst_port:
            return False
        lo, hi = self.window(t0)
        return lo <= start_time <= hi


def load_labels(path: str) -> Dict[str, str]:
    """Per-flow labels: 5-tuple key -> label."""
    labels = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            key = f"{row['src_ip']}-{row['dst_ip']}-{row['src_port']}-{row['dst_port']}-{row['protocol']}"
            labels[key] = row["label"]
    logger.info("Loaded %d flow labels from %s", len(labels), path)
    return labels


def load_attacks(path: str) -> List[AttackRule]:
    out = []
    with open(path) as f:
        for row in csv.DictReader(f):
            port = (row.get("dst_port") or "").strip()
            out.append(AttackRule(
                label=row["label"].strip(), src_ip=row["src_ip"].strip(),
                dst_ip=(row.get("dst_ip") or "").strip(),
                dst_port=int(port) if port else None,
                start=(row.get("start") or "").strip() or None,
                end=(row.get("end") or "").strip() or None,
            ))
    logger.info("Loaded %d attack windows from %s", len(out), path)
    return out


def flow_key_str(key) -> str:
    src, dst, sp, dp, proto = key
    return f"{src}-{dst}-{sp}-{dp}-{proto}"


def true_label(key, start_time, t0, labels, attacks) -> str:
    if labels:
        src, dst, sp, dp, proto = key
        for k in (flow_key_str(key), flow_key_str((dst, src, dp, sp, proto))):
            if k in labels:
                return labels[k]
    for rule in attacks or ():
        if rule.matches(key, start_time, t0):
            return rule.label
    return BENIGN


# ── metrics ────────────────────────────────────────────────────────────────

@dataclass
class EvalResult:
    """Per-flow predictions plus the metrics derived from them."""
    predictions: List[dict] = field(default_factory=list)

    def _counts(self, flt=None, thr=None):
        tp = fp = tn = fn = 0
        for p in self.predictions:
            if flt and not flt(p):
                continue
            attack = p["true_label"] != BENIGN
            hit = p["is_anomaly"] if thr is None else p["ensemble_score"] >= thr
            if attack and hit:
                tp += 1
            elif attack:
                fn += 1
            elif hit:
                fp += 1
            else:
                tn += 1
        return tp, fp, tn, fn

    @property
    def tp(self): return self._counts()[0]
    @property
    def fp(self): return self._counts()[1]
    @property
    def tn(self): return self._counts()[2]
    @property
    def fn(self): return self._counts()[3]

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 1e-9)

    @property
    def accuracy(self) -> float:
        tp, fp, tn, fn = self._counts()
        return (tp + tn) / max(tp + fp + tn + fn, 1)

    @staticmethod
    def _rates(tp, fp, tn, fn) -> dict:
        return {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(tp / max(tp + fp, 1), 4),
            "recall": round(tp / max(tp + fn, 1), 4),
            "fp_rate": round(fp / max(fp + tn, 1), 4),
        }

    def per_class(self) -> Dict[str, dict]:
        out = {}
        for label in sorted({p["true_label"] for p in self.predictions} - {BENIGN}):
            rows = [p for p in self.predictions if p["true_label"] == label]
            detected = [p for p in rows if p["is_anomaly"]]
            rule_counts = Counter(r for p in detected for r in p["triggered_rules"])
            out[label] = {
                "flows": len(rows), "detected": len(detected),
                "recall": round(len(detected) / max(len(rows), 1), 4),
                "top_rules": dict(rule_counts.most_common(3)),
            }
        return out

    def sweep(self, thresholds=SWEEP) -> Dict[str, dict]:
        res = {}
        for t in thresholds:
            tp, fp, tn, fn = self._counts(thr=t)
            res[str(t)] = self._rates(tp, fp, tn, fn)
        return res

    def to_dict(self) -> dict:
        tp, fp, tn, fn = self._counts()
        d = {"total_flows": len(self.predictions), "accuracy": round(self.accuracy, 4),
             "f1": round(self.f1, 4)}
        d.update(self._rates(tp, fp, tn, fn))
        return d


# ── replay ─────────────────────────────────────────────────────────────────

def run_detection(record, flow_vec, host_vec, payload_matches) -> dict:
    """Run all engines on one flow and return the prediction dict."""
    scores = EngineScores()

    # Same calls as the live dispatcher/pipeline: payload features go to the supervised engine,
    # and benign labels are recognised by src.labels.is_benign ("Benign", "BENIGN", ...).
    payload_features = extract_payload_features(record.fwd_payloads)
    if flow_vec is not None and supervised.is_available:
        result = supervised.predict(flow_vec, payload_features)
        if result:
            label, conf = result
            scores.supervised = 0.0 if is_benign(label) else conf
            scores.attack_type = label
            scores.supervised_confidence = conf

    if host_vec is not None and iforest.is_available:
        scores.isolation_forest = iforest.anomaly_score(host_vec)

    if host_vec is not None and lstm.is_available:
        lstm.update(record.key[0], host_vec)
        scores.lstm = lstm.anomaly_score(record.key[0])

    # Baseline engine (live-trained model loaded from MLflow when MLFLOW_TRACKING_URI is set),
    # fed in the same order as src/pipeline.py: update the ring buffer, then score.
    if host_vec is not None and baseline.is_available:
        baseline.update(record.key[0], host_vec)
        scores.baseline = baseline.anomaly_score(record.key[0], host_vec)

    if flow_vec is not None:
        rule_score, triggered = rules.evaluate(record, flow_vec, payload_matches)
        scores.rules = rule_score
        scores.triggered_rules = triggered

    result = ensemble.score(scores)

    # Ablation: the same flow scored with one engine switched off (None = "no opinion", so the
    # scorer redistributes its weight). Shows which engine pushes a flow over the threshold.
    ablation = {}
    for name in ENGINE_FIELDS:
        if getattr(scores, name) is None:
            continue
        r = ensemble.score(replace(scores, **{name: None}))
        ablation[name] = {"score": round(r.score, 4), "is_anomaly": bool(r.is_anomaly)}

    return {
        "engine_scores": {n: (None if getattr(scores, n) is None else round(float(getattr(scores, n)), 4))
                          for n in ENGINE_FIELDS},
        "ablation": ablation,
        "flow_key": flow_key_str(record.key),
        "src_ip": record.key[0],
        "dst_ip": record.key[1],
        "dst_port": record.key[3],
        "ensemble_score": round(result.score, 4),
        "is_anomaly": bool(result.is_anomaly),
        "attack_type": scores.attack_type,
        "active_engines": result.active_engines,
        "triggered_rules": list(scores.triggered_rules or []),
    }


def replay_pcap(pcap_path: str, labels=None, attacks=None) -> EvalResult:
    """Replay one PCAP, scoring flows as they expire (capture time), like the live path."""
    logger.info("Processing %s", pcap_path)
    flow_extractor = FlowExtractor()
    host_extractor = HostExtractor()
    # Payload hits belong to their own flow (as in the live pipeline), never to the whole source host.
    payload_hits: Dict[tuple, List[str]] = defaultdict(list)
    result = EvalResult()
    state: Dict[str, float] = {"t0": 0.0}
    started = False

    def score(batch, now):
        for record, flow_vec in batch:
            host_vec = host_extractor.extract_features(record.key[0], now=now)
            matches = list(set(payload_hits.get(record.key, [])))
            pred = run_detection(record, flow_vec, host_vec, matches)
            pred["true_label"] = true_label(
                record.key, record.start_time, state["t0"], labels, attacks)
            result.predictions.append(pred)

    pkt_count = 0
    ts = 0.0
    last_expire = 0.0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            ts = float(pkt.time)
            if not started:
                started = True
                state["t0"] = ts
                last_expire = ts
            flow_ref = flow_extractor.process_packet(pkt, timestamp=ts)
            host_extractor.process_packet(pkt, timestamp=ts)
            matches = analyze_payload(pkt)
            if matches and flow_ref:
                payload_hits[flow_ref[0]].extend(matches)
            pkt_count += 1
            if ts - last_expire >= EXPIRE_EVERY_S:
                score(flow_extractor.collect_expired(now=ts), ts)
                last_expire = ts

    end = ts if pkt_count else 0.0
    score(flow_extractor.collect_all(), end)
    logger.info("Processed %d packets, scored %d flows", pkt_count, len(result.predictions))
    return result


# ── report ─────────────────────────────────────────────────────────────────

def engines_available() -> dict:
    return {"supervised": supervised.is_available, "isolation_forest": iforest.is_available,
            "lstm": lstm.is_available, "baseline": baseline.is_available, "rules": True}


def markdown_report(agg: EvalResult, files: List[str], threshold: float) -> str:
    lines = ["# CNDS detection coverage (PCAP replay)", "",
             f"Files: {', '.join(files)}", f"Ensemble threshold: {threshold}", "",
             "Engines available: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in engines_available().items()),
             ""]
    info = baseline.get_info()
    if info["available"]:
        lines += [f"Baseline model: version {info['version']} (LSTM threshold {info['threshold']:.3f}). "
                  "It was trained on the live network it came from, not on this capture.", ""]
    else:
        lines += ["Baseline engine not loaded (set MLFLOW_TRACKING_URI to the MLflow that holds "
                  "`cnds-unsupervised-baseline`). Without it the scorer redistributes its weight "
                  "onto the other engines, so scores are NOT comparable with a deployment that has it.", ""]
    lines += ["Not covered: threat-intel boosts, per-(src, type) dedup, suppression rules.", ""]
    lines += ["## Recall per attack class", "", "| Class | Flows | Detected | Recall | Rules that fired |", "|---|---|---|---|---|"]
    for label, d in agg.per_class().items():
        rules_txt = ", ".join(f"{r} ({n})" for r, n in d["top_rules"].items()) or "none"
        lines.append(f"| {label} | {d['flows']} | {d['detected']} | {d['recall']:.0%} | {rules_txt} |")
    _tp, fp, tn, _fn = agg._counts()
    lines += ["", "## Mean engine score per class", "",
              "| Class | " + " | ".join(ENGINE_FIELDS) + " |", "|---|" + "---|" * len(ENGINE_FIELDS)]
    for label in ["BENIGN"] + list(agg.per_class()):
        rows = [p for p in agg.predictions if p["true_label"] == label]
        cells = []
        for n in ENGINE_FIELDS:
            vals = [p["engine_scores"][n] for p in rows if p["engine_scores"][n] is not None]
            cells.append(f"{sum(vals) / len(vals):.2f}" if vals else "-")
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += ["", "## Ablation: switch one engine off", "",
              "Flows flagged when the engine is removed and its weight redistributed "
              "(a large drop in false positives points at the engine producing them).", "",
              "| Engine removed | Benign flagged | Attack recall |", "|---|---|---|"]
    ben = [p for p in agg.predictions if p["true_label"] == BENIGN]
    att = [p for p in agg.predictions if p["true_label"] != BENIGN]
    base_fp = sum(p["is_anomaly"] for p in ben)
    base_tp = sum(p["is_anomaly"] for p in att)
    lines.append(f"| none (baseline run) | {base_fp}/{len(ben)} | {base_tp}/{len(att)} |")
    for n in ENGINE_FIELDS:
        if not any(n in p["ablation"] for p in agg.predictions):
            continue
        fp_n = sum(p["ablation"].get(n, {"is_anomaly": p["is_anomaly"]})["is_anomaly"] for p in ben)
        tp_n = sum(p["ablation"].get(n, {"is_anomaly": p["is_anomaly"]})["is_anomaly"] for p in att)
        lines.append(f"| {n} | {fp_n}/{len(ben)} | {tp_n}/{len(att)} |")
    lines += ["", "## Benign traffic", "",
              f"{fp + tn} benign flows, {fp} flagged (false-positive rate {fp / max(fp + tn, 1):.1%}).", "",
              "## Threshold sweep (score >= threshold)", "",
              "| Threshold | Recall | FP rate | Precision |", "|---|---|---|---|"]
    for t, r in agg.sweep().items():
        lines.append(f"| {t} | {r['recall']:.0%} | {r['fp_rate']:.1%} | {r['precision']:.0%} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="PCAP replay and detection-coverage measurement")
    parser.add_argument("pcap_files", nargs="+", help="PCAP file(s) to process")
    parser.add_argument("--labels", help="CSV with per-flow ground-truth labels")
    parser.add_argument("--attacks", help="CSV with attack windows (label,src_ip,dst_ip,dst_port,start,end)")
    parser.add_argument("--output", "-o", default="eval_results.json", help="Output JSON file")
    parser.add_argument("--report", help="Also write a Markdown report here")
    parser.add_argument("--threshold", type=float, help="Override ensemble threshold")
    args = parser.parse_args()

    from src import config
    if args.threshold:
        config.ENSEMBLE_THRESHOLD = args.threshold

    labels = load_labels(args.labels) if args.labels else None
    attacks = load_attacks(args.attacks) if args.attacks else None

    aggregate = EvalResult()
    per_file = {}
    used = []
    for pcap_path in args.pcap_files:
        if not Path(pcap_path).exists():
            logger.warning("File not found: %s", pcap_path)
            continue
        res = replay_pcap(pcap_path, labels, attacks)
        used.append(pcap_path)
        per_file[pcap_path] = {"metrics": res.to_dict(), "per_class": res.per_class(),
                               "predictions": res.predictions}
        aggregate.predictions.extend(res.predictions)

    out = {"files": per_file, "aggregate": aggregate.to_dict(),
           "per_class": aggregate.per_class(), "threshold_sweep": aggregate.sweep(),
           "threshold": config.ENSEMBLE_THRESHOLD, "engines": engines_available()}
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    logger.info("Results written to %s", args.output)
    logger.info("Aggregate: P=%.3f R=%.3f F1=%.3f", aggregate.precision, aggregate.recall, aggregate.f1)
    if args.report:
        Path(args.report).write_text(markdown_report(aggregate, used, config.ENSEMBLE_THRESHOLD))
        logger.info("Report written to %s", args.report)


if __name__ == "__main__":
    main()
