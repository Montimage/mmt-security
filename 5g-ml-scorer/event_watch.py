"""Watch an mmt-probe EVENT-report folder and score each completed window with the event
model + the dup-MAC rule. Online counterpart of event_pipeline.py.

Same launcher contract as watch.py, so an mmt-security rule can (re)launch it freely:
  --lock-file   : idempotent singleton — if another scorer already holds it, exit at once.
                  (rule fires on every 5G session; repeated launches no-op instead of piling up.)
  --idle-timeout: exit after N seconds with no new report — self-terminates when traffic stops.

Each rotation-window CSV (format id 1000) is aggregated by event_features into ONE per-window
feature vector, scored by the RF model AND the dup-MAC rule, and one alert is emitted per
flagged window (naming which detector fired and the duplicated MAC, for localization).

    python event_watch.py --model models/rf_event.joblib \
        --watch-dir /opt/mmt/probe/result/report/online \
        --lock-file /tmp/mmt-event-scorer.lock --idle-timeout 60 --alerts alerts.log

Required mmt-probe.conf settings (live, so windows rotate with a semaphore per window):
    event-report ngap_nas { enable = true ; ... }   # same block extract_event.sh appends
    session-report.enable    = false                 # we only want the 1000 event rows
    output.format            = CSV
    file-output.enable       = true
    file-output.sample-file  = true       # REQUIRED — no .sem semaphore is written otherwise
    output.cache-period      = <sec>      # == window length; set it near the training capture length
    file-output.retain-files = <large>    # keep files long enough for the watcher to consume
"""

import argparse
import fcntl
import glob
import json
import os
import shutil
import time

import joblib
import pandas as pd

from event_features import (describe_replay, featurize_capture, load_event_file,
                            load_sctp_file)
from stix_kafka import (KAFKA_BROKER, KAFKA_PASSWORD, KAFKA_TOPIC, KAFKA_USERNAME,
                        STIX_RULE_ID, KafkaStixSender, build_stix_bundle, serialize)

# Predicted class -> human attack name for the alert + STIX x-attack-type.
CLASS_TO_ATTACK_NAME = {
    "replay":    "NAS Replay Attack",
    "flooding":  "5G Signalling Flooding",
    "malformed": "Malformed NGAP Injection",
    "normal":    None,        # not an attack -> no alert
}

SEM_EXT = ".csv.sem"  # matches SEMAPHORE_EXT in mmt-probe file_output.c


def _acquire_lock(lock_file):
    """Exclusive non-blocking lock so only one scorer runs. Returns the open handle (keep it
    alive; released on process exit) or None if another instance already holds it."""
    handle = open(lock_file, "w")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def _load_artifact(path):
    art = joblib.load(path)
    if "feature_cols" not in art or "model" not in art:
        raise ValueError(f"{path} is not an event model artifact (expected keys model/feature_cols). "
                         f"Train one with: event_pipeline.py train")
    kind = "multi-class " + "/".join(art.get("classes", [])) if art.get("multiclass") else "binary"
    print(f"Loaded {kind} event model from {path} ({len(art['feature_cols'])} features)")
    return art


def process_file_multiclass(csv_path, art, min_nas, alert_sink, stix_sink=None):
    """Score one window with a multi-class model: predict the attack family and, unless it's
    'normal', raise one alert naming that class. Returns 1 if an alert was emitted."""
    df = load_event_file(csv_path)
    sctp_df = load_sctp_file(csv_path)          # needed for the malformed features
    feat = featurize_capture(df, sctp_df if len(sctp_df) else None)
    # Skip windows with no signalling at all (idle/boundary). Malformed has few NGAP rows but
    # many SCTP DATA chunks, so gate on either being present, not on n_nas alone.
    if feat.get("n_msgs", 0) == 0 and feat.get("n_sctp_data", 0) == 0:
        return 0
    cols = art["feature_cols"]
    X = pd.DataFrame([{c: feat.get(c, 0) for c in cols}])[cols].to_numpy()
    cls = str(art["model"].predict(X)[0])
    attack_name = CLASS_TO_ATTACK_NAME.get(cls, cls)
    if attack_name is None:                     # predicted 'normal'
        return 0

    rep = describe_replay(df)                   # IPs / dup-MAC detail for context
    src_ip, dst_ip = rep["src_ip"], rep["dst_ip"]
    if not src_ip:                              # ciphered replay / malformed have no readable
        src_ip, dst_ip = _fallback_endpoints(df, sctp_df)   # NAS; take IPs from any row
    description = (
        f"{attack_name} detected in window {os.path.basename(csv_path)}: "
        f"class={cls} dup_concentration={feat.get('dup_concentration', 0):.2f} "
        f"n_dup_macs={int(feat.get('n_dup_macs', 0))} max_mac_mult={int(feat.get('max_mac_mult_any', 0))} "
        f"frac_no_ngap={feat.get('frac_no_ngap', 0):.2f} "
        f"n_msgs={int(feat.get('n_msgs', 0))} n_sctp_data={int(feat.get('n_sctp_data', 0))} "
        f"src={src_ip} dst={dst_ip}"
    )
    alert_sink(f"ALERT {os.path.basename(csv_path)} [{cls}] {attack_name}: " + description)
    if stix_sink:
        # the exact input datapoint the model scored (ordered as feature_cols), for AVA's xAI
        datapoint = {c: _num(feat.get(c, 0)) for c in cols}
        stix_sink(description, src_ip, dst_ip, os.path.basename(csv_path), attack_name,
                  features=datapoint, predicted_class=cls,
                  model_name=art.get("model_name", "rf_event_multiclass"))
    return 1


def _num(v):
    """JSON-serialisable scalar (numpy types -> python int/float)."""
    try:
        f = float(v)
        return int(f) if f.is_integer() else f
    except (TypeError, ValueError):
        return v


def _fallback_endpoints(df, sctp_df):
    """Most common (src, dst) IP pair from whatever rows carry them — used when the NAS is
    ciphered/garbage so describe_replay found none."""
    for frame in (df, sctp_df):
        if frame is not None and len(frame) and "ip_src" in frame:
            s = frame["ip_src"][frame["ip_src"].astype(str) != ""]
            d = frame["ip_dst"][frame["ip_dst"].astype(str) != ""]
            if len(s) and len(d):
                return str(s.value_counts().index[0]), str(d.value_counts().index[0])
    return "", ""


def process_file(csv_path, art, min_mult, min_nas, require, alert_sink, stix_sink=None):
    """Score one window CSV. Returns 1 if an alert was emitted, else 0."""
    if art.get("multiclass"):
        return process_file_multiclass(csv_path, art, min_nas, alert_sink, stix_sink)
    df = load_event_file(csv_path)
    if df.empty:
        return 0
    feat = featurize_capture(df)
    # Skip windows with too little NAS signalling to classify (idle / boundary chunks). The
    # model was trained on full-registration captures, so it over-fires on near-empty windows.
    if feat.get("n_nas", 0) < min_nas:
        return 0
    X = pd.DataFrame([{c: feat.get(c, 0) for c in art["feature_cols"]}])[art["feature_cols"]].to_numpy()
    model_pred = int(art["model"].predict(X)[0])
    rule_pred = int(feat.get("max_mac_mult", 0) >= min_mult)

    # Which detector(s) must fire to raise an alert. 'both' (model AND rule agree) is the clean
    # choice online: the rule never false-positives, so it gates the model's over-firing.
    fire = {"any": model_pred or rule_pred, "both": model_pred and rule_pred,
            "rule": rule_pred, "model": model_pred}[require]
    if not fire:
        return 0

    who = "+".join([w for w, p in (("model", model_pred), ("rule", rule_pred)) if p])
    # Everything identifying the attack — which MAC repeated, which 5GMM message it
    # carried, and between which IPs — is read out of this window's CSV.
    rep = describe_replay(df)
    mac = rep["mac"]
    attack_name = rep["label"]          # e.g. "NAS Security Mode Command replay"
    description = (
        f"5G {attack_name} detected by {who} in window {os.path.basename(csv_path)}: "
        f"replayed={'/'.join(rep['msg_names']) or 'n/a'} "
        f"src={rep['src_ip']} dst={rep['dst_ip']} "
        f"dup_mac={mac} max_mac_mult={int(feat['max_mac_mult'])} "
        f"dup_mac_ratio={feat['dup_mac_ratio']:.2f} n_nas={int(feat['n_nas'])} "
        f"n_msgs={int(feat['n_msgs'])}"
    )
    alert_sink(
        f"ALERT {os.path.basename(csv_path)} [{who}] {attack_name}: "
        f"replayed={'/'.join(rep['msg_names']) or 'n/a'} "
        f"dup_mac_ratio={feat['dup_mac_ratio']:.2f} max_mac_mult={int(feat['max_mac_mult'])} "
        f"dup_mac={mac} n_nas={feat['n_nas']} n_msgs={feat['n_msgs']}"
    )
    if stix_sink:
        stix_sink(description, rep["src_ip"], rep["dst_ip"],
                  os.path.basename(csv_path), attack_name)
    return 1


def _make_alert_sink(alerts_path):
    def sink(line):
        print(line, flush=True)
        if alerts_path:
            with open(alerts_path, "a") as f:
                f.write(line + "\n")
    return sink


def _archive(csv_path, sem_path, processed_dir):
    if not processed_dir:
        return
    os.makedirs(processed_dir, exist_ok=True)
    for p in (csv_path, sem_path):
        try:
            shutil.move(p, os.path.join(processed_dir, os.path.basename(p)))
        except (FileNotFoundError, OSError):
            pass


def scan_once(art, watch_dir, processed_dir, min_mult, min_nas, require, alert_sink,
              stix_sink=None, allow_no_sem=False):
    sems = sorted(glob.glob(os.path.join(watch_dir, "*" + SEM_EXT)), key=os.path.getmtime)
    n_files = n_alerts = 0
    for sem in sems:
        csv_path = sem[: -len(".sem")]
        if not os.path.exists(csv_path):
            _archive(csv_path, sem, processed_dir)
            continue
        try:
            n_alerts += process_file(csv_path, art, min_mult, min_nas, require, alert_sink, stix_sink)
            n_files += 1
        except Exception as e:                      # never let one bad file kill the watcher
            print(f"  error processing {os.path.basename(csv_path)}: {e}", flush=True)
        finally:
            _archive(csv_path, sem, processed_dir)

    # Offline convenience: a folder of extract_event.sh CSVs has NO .sem semaphores (those are
    # only written live, sample-file=true). With --once we score the CSVs directly and DON'T
    # move them (they are the user's files, not rotating windows).
    if allow_no_sem and not sems:
        for csv_path in sorted(glob.glob(os.path.join(watch_dir, "*.csv"))):
            if os.path.basename(os.path.dirname(csv_path)) == "processed":
                continue
            try:
                n_alerts += process_file(csv_path, art, min_mult, min_nas, require, alert_sink, stix_sink)
                n_files += 1
            except Exception as e:
                print(f"  error processing {os.path.basename(csv_path)}: {e}", flush=True)
    return n_files, n_alerts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="event model artifact from event_pipeline.py train")
    ap.add_argument("--watch-dir", required=True, help="mmt-probe file-output.output-dir (event reports)")
    ap.add_argument("--processed-dir", default=None, help="move processed files here (default <watch-dir>/processed)")
    ap.add_argument("--min-mult", type=int, default=3, help="dup-MAC rule threshold (max_mac_mult >= this)")
    ap.add_argument("--min-nas", type=int, default=1, help="skip windows with fewer than N NAS messages (idle/boundary)")
    ap.add_argument("--require", choices=["any","both","rule","model"], default="both",
                    help="which detector(s) must fire to alert. both = model AND rule agree (clean; default)")
    ap.add_argument("--alerts", default=None, help="append alerts to this file as well as stdout")
    ap.add_argument("--poll", type=float, default=1.0, help="seconds between scans")
    ap.add_argument("--once", action="store_true", help="process existing files once and exit")
    ap.add_argument("--lock-file", default=None, help="singleton lock; exit if another scorer holds it")
    ap.add_argument("--idle-timeout", type=float, default=0.0,
                    help="exit after N seconds with no new reports (0 = run forever)")
    # ---- STIX / Kafka output channel. Values come from the .env file beside stix_kafka.py;
    #      these flags are only an override. Disabled unless --kafka is given.
    ap.add_argument("--kafka", action="store_true", help="publish each alert to Kafka as a STIX 2.1 bundle")
    ap.add_argument("--kafka-broker", default=KAFKA_BROKER,
                    help="Kafka broker 'hostname:port' (default: MMT_KAFKA_BROKER from .env)")
    ap.add_argument("--kafka-topic", default=KAFKA_TOPIC,
                    help="Kafka topic to publish to (default: MMT_KAFKA_TOPIC from .env)")
    ap.add_argument("--kafka-username", default=KAFKA_USERNAME,
                    help="SASL username; empty = no auth (default: MMT_KAFKA_USERNAME from .env)")
    ap.add_argument("--kafka-password", default=KAFKA_PASSWORD,
                    help="SASL password (default: MMT_KAFKA_PASSWORD from .env; do NOT pass on the CLI)")
    ap.add_argument("--stix-dir", default=None,
                    help="write each alert as a pretty-printed STIX .json file here (no Kafka needed)")
    ap.add_argument("--stix-file", default=None,
                    help="append every STIX bundle to one NDJSON file (no Kafka needed)")
    args = ap.parse_args()

    lock_handle = None
    if args.lock_file:
        lock_handle = _acquire_lock(args.lock_file)
        if lock_handle is None:
            print(f"Another scorer already holds {args.lock_file}; exiting.")
            return

    art = _load_artifact(args.model)
    processed_dir = args.processed_dir or os.path.join(args.watch_dir, "processed")
    alert_sink = _make_alert_sink(args.alerts)
    sender, stix_sink = _make_stix_sink(args)

    try:
        if args.once:
            f, a = scan_once(art, args.watch_dir, processed_dir, args.min_mult, args.min_nas,
                             args.require, alert_sink, stix_sink, allow_no_sem=True)
            print(f"Done: {f} window(s), {a} alert(s).")
            return
        _watch_loop(args, art, processed_dir, alert_sink, stix_sink, sender)
    finally:
        if sender:
            sender.close()   # flush queued bundles before the scorer self-terminates


def _make_stix_sink(args):
    """Returns (sender, sink) — sink(description, src_ip, dst_ip, name) emits one STIX bundle
    to whichever outputs were requested. (None, None) when none were.

    The three outputs are independent: --stix-dir / --stix-file work with NO Kafka at all,
    which is the way to inspect the format before pointing at a real broker.
    """
    if not (args.kafka or args.stix_file or args.stix_dir):
        return None, None
    sender = KafkaStixSender(args.kafka_broker, args.kafka_topic,
                             args.kafka_username, args.kafka_password) if args.kafka else None
    if args.stix_dir:
        os.makedirs(args.stix_dir, exist_ok=True)
        print(f"STIX bundles -> {args.stix_dir}/ (one .json per alert)")

    def sink(description, src_ip, dst_ip, name="alert", attack_name=None,
             features=None, predicted_class=None, model_name=None):
        bundle = build_stix_bundle(description, src_ip, dst_ip, rule_id=STIX_RULE_ID,
                                   attack_name=attack_name, features=features,
                                   predicted_class=predicted_class, model_name=model_name)
        if args.stix_dir:
            # One pretty-printed bundle per alert, named after the window it came from.
            # The bundle-uuid tail keeps two alerts on the same window from colliding.
            base = os.path.splitext(os.path.basename(name))[0]
            path = os.path.join(args.stix_dir, f"stix_{base}_{bundle['id'][-8:]}.json")
            with open(path, "w") as f:
                f.write(serialize(bundle))
            print(f"  -> STIX bundle written to {path}", flush=True)
        if args.stix_file:
            with open(args.stix_file, "a") as f:
                f.write(json.dumps(bundle) + "\n")   # NDJSON: one compact bundle per line
        if sender and sender.send(bundle):
            # Only QUEUED here — the broker's ack arrives later via the delivery callback,
            # which prints "DELIVERED ... offset N". Don't read this line as success.
            print(f"  -> STIX bundle queued for Kafka topic '{args.kafka_topic}'", flush=True)

    return sender, sink


def _watch_loop(args, art, processed_dir, alert_sink, stix_sink, sender=None):
    print(f"Watching {args.watch_dir} (poll {args.poll}s, idle-timeout {args.idle_timeout or '∞'}s). "
          f"Processed -> {processed_dir}. Ctrl-C to stop.")
    total_f = total_a = 0
    last_activity = time.monotonic()
    try:
        while True:
            f, a = scan_once(art, args.watch_dir, processed_dir, args.min_mult, args.min_nas,
                             args.require, alert_sink, stix_sink)
            total_f += f
            total_a += a
            if sender:
                sender.poll()   # surface Kafka delivery acks/errors while we run
            if f:
                last_activity = time.monotonic()
                print(f"  [scan] {f} window(s), {a} alert(s)  (cumulative: {total_f} windows, {total_a} alerts)", flush=True)
            elif args.idle_timeout and (time.monotonic() - last_activity) > args.idle_timeout:
                print(f"No new reports for {args.idle_timeout:.0f}s; exiting. "
                      f"Processed {total_f} window(s), {total_a} alert(s) total.")
                break
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print(f"\nStopped. Processed {total_f} window(s), {total_a} alert(s) total.")


if __name__ == "__main__":
    main()
