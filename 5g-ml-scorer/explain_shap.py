"""Explain the 5G NAS-replay event model with SHAP.

WHAT SHAP NEEDS
  1. the trained model            -> models/rf_event_2core.joblib
  2. data to explain              -> a folder of event CSVs (the same format the scorer eats)
A model alone is NOT enough. SHAP answers "why did the model score THIS input the way it
did", so it always needs feature vectors. For a global picture it needs a set of them.

Our model is a RandomForest, so TreeExplainer applies: exact Shapley values, no sampling,
and no separate background dataset required (it walks the trees' own path statistics).
That is why this runs in seconds instead of minutes.

    python explain_shap.py --data-dir ../free5gc-event-csv            # global ranking
    python explain_shap.py --data-dir ../free5gc-event-csv --plots    # + summary/bar PNGs
    python explain_shap.py --data-dir ../free5gc-event-csv --csv shap_values.csv
    python explain_shap.py --data-dir ../free5gc-event-csv --explain-window 3

Reading the numbers: SHAP values are additive contributions in the model's output space.
For one window,  base_value + sum(shap values) = predicted probability of "attack".
A positive value pushed that window towards ATTACK, a negative one towards NORMAL.
"""

import argparse
import os

import joblib
import numpy as np
import pandas as pd

from event_features import FEATURE_COLS, GROUP_COL, LABEL_COL, load_event_dataset


def load_model(path):
    art = joblib.load(path)
    if "model" not in art or "feature_cols" not in art:
        raise ValueError(f"{path} is not an event model artifact")
    return art["model"], art["feature_cols"]


def shap_for(model, X):
    """Exact SHAP values for the ATTACK class of a tree model.

    shap returns different shapes across versions/estimators: (n,f) for a single output,
    or (n,f,2)/[array,array] for the two classes of a binary classifier. Normalise to the
    positive ("attack") class so callers always get an (n_samples, n_features) matrix.
    """
    import shap
    explainer = shap.TreeExplainer(model)
    values = explainer.shap_values(X)
    if isinstance(values, list):                 # [class0, class1]
        values, base = values[1], explainer.expected_value[1]
    elif getattr(values, "ndim", 2) == 3:        # (n, f, n_classes)
        values, base = values[..., 1], explainer.expected_value[1]
    else:
        base = explainer.expected_value
        base = base[0] if np.ndim(base) else base
    return np.asarray(values), float(base)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="models/rf_event_2core.joblib")
    ap.add_argument("--data-dir", required=True, help="folder of event CSVs to explain")
    ap.add_argument("--plots", action="store_true", help="write beeswarm + bar PNGs")
    ap.add_argument("--out-dir", default="shap-out", help="where plots/CSV go")
    ap.add_argument("--csv", default=None, help="write per-window SHAP values to this CSV")
    ap.add_argument("--explain-window", type=int, default=None,
                    help="print a single window's full contribution breakdown (row index)")
    args = ap.parse_args()

    model, feature_cols = load_model(args.model)
    df = load_event_dataset(args.data_dir)
    if df.empty:
        raise SystemExit(f"no event CSVs found in {args.data_dir}")
    X = df[feature_cols].to_numpy()
    y = df[LABEL_COL].to_numpy() if LABEL_COL in df else None
    print(f"Explaining {len(df)} window(s) x {len(feature_cols)} features "
          f"from {args.data_dir}")

    values, base = shap_for(model, X)
    print(f"base value (model's average output) = {base:.4f}\n")

    # ---- global: which features drive the model overall -------------------------------
    mean_abs = np.abs(values).mean(axis=0)
    order = np.argsort(mean_abs)[::-1]
    total = mean_abs.sum() or 1.0
    print("GLOBAL feature importance (mean |SHAP|, share of total):")
    for i in order:
        bar = "#" * int(round(40 * mean_abs[i] / (mean_abs[order[0]] or 1)))
        print(f"  {feature_cols[i]:<20} {mean_abs[i]:.4f}  {100*mean_abs[i]/total:5.1f}%  {bar}")

    # ---- local: one window, fully decomposed ------------------------------------------
    if args.explain_window is not None:
        i = args.explain_window
        if not 0 <= i < len(df):
            raise SystemExit(f"--explain-window must be in 0..{len(df)-1}")
        contrib = values[i]
        pred = model.predict(X[i:i + 1])[0]
        print(f"\nWINDOW {i}: {df.iloc[i].get(GROUP_COL, '?')}")
        print(f"  true label={y[i] if y is not None else '?'}  predicted={pred}  "
              f"p(attack)={base + contrib.sum():.4f}")
        print(f"  {'feature':<20} {'value':>12} {'SHAP':>10}  effect")
        for j in np.argsort(np.abs(contrib))[::-1]:
            arrow = "-> ATTACK" if contrib[j] > 0 else "-> normal"
            print(f"  {feature_cols[j]:<20} {X[i, j]:>12.4f} {contrib[j]:>+10.4f}  "
                  f"{arrow if abs(contrib[j]) > 1e-9 else ''}")

    # ---- export for the partner's own explainability tool -----------------------------
    if args.csv:
        out = pd.DataFrame(values, columns=[f"shap_{c}" for c in feature_cols])
        for c in feature_cols:
            out[f"value_{c}"] = df[c].to_numpy()
        if GROUP_COL in df:
            out.insert(0, GROUP_COL, df[GROUP_COL].to_numpy())
        if y is not None:
            out.insert(1, LABEL_COL, y)
        out["base_value"] = base
        out.to_csv(args.csv, index=False)
        print(f"\nPer-window SHAP values -> {args.csv}")

    if args.plots:
        try:
            import matplotlib
        except ImportError:
            raise SystemExit("--plots needs matplotlib: pip install matplotlib "
                             "(the text output above needs no extra package)")
        matplotlib.use("Agg")            # headless: works over SSH on the VM
        import matplotlib.pyplot as plt
        import shap
        os.makedirs(args.out_dir, exist_ok=True)
        for kind in ("dot", "bar"):
            shap.summary_plot(values, pd.DataFrame(X, columns=feature_cols),
                              plot_type=kind, show=False)
            p = os.path.join(args.out_dir, f"shap_summary_{kind}.png")
            plt.tight_layout(); plt.savefig(p, dpi=150); plt.close()
            print(f"plot -> {p}")


if __name__ == "__main__":
    main()
