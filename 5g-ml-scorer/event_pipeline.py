"""Portable NGAP/NAS replay detector over event-report (format-1000) features.

One feature vector per capture (event_features.py). Modes:

  # 1) honest within-testbed estimate (leave-one-capture-out) + the rule baseline
  python event_pipeline.py eval  --data-dir ../open5gs-event-csv

  # 2) fit on all new-testbed captures and save an artifact
  python event_pipeline.py train --data-dir ../open5gs-event-csv --out models/rf_event.joblib

  # 3) apply that model to another core's captures (the generalization test)
  python event_pipeline.py score --model models/rf_event.joblib --data-dir ../old-event-csv

The rule baseline (duplicate NAS-MAC) is reported alongside the model everywhere, because for
a byte-replay attack it is both interpretable and inherently core-invariant.
"""

import argparse
import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (balanced_accuracy_score, classification_report,
                             confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import LeaveOneGroupOut

from event_features import (CLASSES, FEATURE_COLS, GROUP_COL, LABEL_COL,
                            MULTICLASS_FEATURE_COLS, load_event_dataset, rule_prediction)


def _build_rf():
    return RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                  random_state=42, n_jobs=-1)


def _report(tag, y, pred):
    if len(set(y)) > 1:
        print(f"  [{tag}] F1={f1_score(y, pred):.3f}  precision={precision_score(y, pred, zero_division=0):.3f}  "
              f"recall={recall_score(y, pred, zero_division=0):.3f}  bal_acc={balanced_accuracy_score(y, pred):.3f}")
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    print(f"  [{tag}] capture confusion: TP={tp} FP={fp} FN={fn} TN={tn}")


def _print_per_capture(df, pred, model_pred=None):
    print(f"\n  {'capture':<64} {'true':<9} {'dupMAC%':>7} {'maxMult':>7} {'rule':>6}" +
          ("  model" if model_pred is not None else ""))
    for i, (_, r) in enumerate(df.iterrows()):
        true = "abnormal" if r[LABEL_COL] == 1 else "normal"
        rule = "REPLAY" if pred[i] else "clean"
        extra = ""
        if model_pred is not None:
            extra = f"  {'REPLAY' if model_pred[i] else 'clean'}"
        print(f"  {r[GROUP_COL][:64]:<64} {true:<9} {100*r['dup_mac_ratio']:>6.0f}% "
              f"{int(r['max_mac_mult']):>7} {rule:>6}{extra}")


def _present_classes(*label_arrays):
    """Class order restricted to those actually present, keeping CLASSES ordering."""
    seen = set()
    for a in label_arrays:
        seen.update(a)
    return [c for c in CLASSES if c in seen]


def _report_multiclass(y, pred):
    labels = _present_classes(y, pred)
    print(classification_report(y, pred, labels=labels, zero_division=0))
    cm = confusion_matrix(y, pred, labels=labels)
    w = max(len(c) for c in labels) + 1
    print("  confusion matrix (rows = true, cols = predicted):")
    print(" " * (w + 2) + " ".join(f"{c[:6]:>7}" for c in labels))
    for i, c in enumerate(labels):
        print(f"  {c:<{w}} " + " ".join(f"{cm[i, j]:>7}" for j in range(len(labels))))


def cmd_eval_multiclass(args):
    df = load_event_dataset(args.data_dir, multiclass=True)
    X = df[MULTICLASS_FEATURE_COLS].to_numpy()
    y = df[LABEL_COL].to_numpy()
    groups = df[GROUP_COL].to_numpy()
    logo = LeaveOneGroupOut()
    oof = np.empty(len(y), dtype=object)
    for tr, te in logo.split(X, y, groups):
        if len(set(y[tr])) < 2:
            oof[te] = y[tr][0]           # degenerate fold: predict the only class seen
            continue
        oof[te] = _build_rf().fit(X[tr], y[tr]).predict(X[te])
    print("\n=== MULTI-CLASS, leave-one-capture-out ===")
    _report_multiclass(y, oof)


def cmd_train_multiclass(args):
    df = load_event_dataset(args.data_dir, multiclass=True)
    X = df[MULTICLASS_FEATURE_COLS].to_numpy()
    y = df[LABEL_COL].to_numpy()
    model = _build_rf().fit(X, y)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({"model": model, "feature_cols": MULTICLASS_FEATURE_COLS,
                 "classes": list(model.classes_), "multiclass": True}, args.out)
    print(f"\nTrained multi-class on {len(y)} captures. Saved -> {args.out}")
    print(f"  classes: {list(model.classes_)}")
    imp = sorted(zip(MULTICLASS_FEATURE_COLS, model.feature_importances_), key=lambda t: -t[1])
    print("  top features: " + ", ".join(f"{n}={v:.2f}" for n, v in imp[:6]))


def cmd_eval(args):
    if getattr(args, "multiclass", False):
        return cmd_eval_multiclass(args)
    df = load_event_dataset(args.data_dir)
    X = df[FEATURE_COLS].to_numpy()
    y = df[LABEL_COL].to_numpy()
    groups = df[GROUP_COL].to_numpy()

    # Leave-one-capture-out out-of-fold predictions.
    logo = LeaveOneGroupOut()
    oof = np.zeros(len(y), dtype=int)
    for tr, te in logo.split(X, y, groups):
        if len(set(y[tr])) < 2:      # a fold with single-class train can't fit a classifier
            oof[te] = 0
            continue
        m = _build_rf().fit(X[tr], y[tr])
        oof[te] = m.predict(X[te])

    rule = rule_prediction(df).to_numpy()
    print("\n=== within-testbed, leave-one-capture-out ===")
    _report("model", y, oof)
    _report("rule ", y, rule)
    _print_per_capture(df, rule, model_pred=oof)


def cmd_train(args):
    if getattr(args, "multiclass", False):
        return cmd_train_multiclass(args)
    df = load_event_dataset(args.data_dir)
    X = df[FEATURE_COLS].to_numpy()
    y = df[LABEL_COL].to_numpy()
    model = _build_rf().fit(X, y)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    joblib.dump({"model": model, "feature_cols": FEATURE_COLS}, args.out)
    print(f"\nTrained on {len(y)} captures ({int(y.sum())} abnormal). Saved -> {args.out}")
    imp = sorted(zip(FEATURE_COLS, model.feature_importances_), key=lambda t: -t[1])
    print("  top features: " + ", ".join(f"{n}={v:.2f}" for n, v in imp[:5]))


def cmd_score(args):
    art = joblib.load(args.model)
    df = load_event_dataset(args.data_dir)
    X = df[art["feature_cols"]].to_numpy()
    y = df[LABEL_COL].to_numpy()
    model_pred = art["model"].predict(X)
    rule = rule_prediction(df).to_numpy()

    print("\n=== cross-core score ===")
    _report("model", y, model_pred)
    _report("rule ", y, rule)
    _print_per_capture(df, rule, model_pred=model_pred)

    norm = df[df[LABEL_COL] == 0]
    if len(norm):
        idx = np.where(y == 0)[0]
        fp_model = int(model_pred[idx].sum())
        fp_rule = int(rule[idx].sum())
        print(f"\n  false positives on {len(norm)} NORMAL captures: model={fp_model}, rule={fp_rule}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    for name in ("eval", "train", "score"):
        s = sub.add_parser(name)
        s.add_argument("--data-dir", required=True)
        if name in ("eval", "train"):
            s.add_argument("--multiclass", action="store_true",
                           help="4-class replay/flooding/malformed/normal instead of binary")
        if name == "train":
            s.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "models", "rf_event.joblib"))
        if name == "score":
            s.add_argument("--model", default=os.path.join(os.path.dirname(__file__), "models", "rf_event.joblib"))
    args = ap.parse_args()
    {"eval": cmd_eval, "train": cmd_train, "score": cmd_score}[args.mode](args)


if __name__ == "__main__":
    main()
