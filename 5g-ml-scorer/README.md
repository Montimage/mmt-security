# 5G multi-class ML scorer

An ML detector for 5G control-plane attacks, driven by MMT. mmt-probe writes NGAP/NAS event
reports; this scorer aggregates each monitoring window into a feature vector, classifies it
with a RandomForest model, and for an attack publishes a STIX 2.1 bundle to Kafka.

It is launched automatically by the mmt-security rule `rules/500.5g_ml_scorer_launcher.xml`
(via an embedded `system()` call), but can also be run by hand (see below).

## Classes
`normal`, `replay` (NAS replay), `flooding` (5G signalling flooding), `malformed` (malformed
NGAP). Only attacks raise an alert; `normal` is silent.

## Files
| file | role |
|------|------|
| `event_watch.py` | online scorer: watches the report dir, scores each window, emits alerts |
| `event_features.py` | turns raw NGAP/NAS event rows into the 12-feature vector |
| `stix_kafka.py` | builds the STIX 2.1 bundle (with the ML feature vector) and sends it to Kafka |
| `event_pipeline.py` | offline train / eval (`--multiclass`) |
| `explain_shap.py` | SHAP feature-importance for the model |
| `models/rf_event_multiclass.joblib` | the trained model (4 classes, 12 features) |
| `requirements.txt` | pinned Python deps (match the versions the model was pickled with) |
| `.env.example` | template for Kafka settings — copy to `.env` and fill in |

## Install
```bash
cd 5g-ml-scorer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then edit .env with your Kafka broker + SASL credentials
```
`.env` and `.venv/` are git-ignored (the `.env` holds credentials — never commit it).

## How it runs in the pipeline
1. mmt-probe captures live 5G traffic and writes rotating NGAP/NAS event-report CSVs (with a
   `.sem` semaphore per completed window) into a watch directory.
2. The mmt-security rule 500 fires on NGAP/NAS traffic and launches this scorer (idempotent;
   self-terminates after `--idle-timeout` seconds of no new reports).
3. For each attack window, the scorer appends an alert to the alerts log and publishes a STIX
   bundle to Kafka. The bundle carries the exact feature vector under
   `observed-data → extensions → x-mmt-features` (for a downstream xAI tool).

Edit the three `#define` paths in `rules/500.5g_ml_scorer_launcher.xml` (SCORER_DIR,
SCORER_WATCH_DIR, SCORER_ALERTS) to match your install before compiling the rules.

## Alert output modes (choose any combination)
The STIX bundle is the same regardless of destination (shared serializer), so a JSON file is a
byte-faithful preview of what Kafka receives:
- `--kafka` — publish each bundle to Kafka (production / AVA; needs `.env`).
- `--stix-dir DIR` — write one pretty-printed `.json` per alert (best for testing, no Kafka).
- `--stix-file FILE` — append every bundle to one NDJSON file.
- `--alerts FILE` — append the one-line human alerts (independent of the STIX outputs).

In the launcher rule, this is the one-line `SCORER_OUTPUT` macro
(`--stix-dir ...` for testing vs `--kafka` for production).

## Run it by hand
Testing — offline on a folder of already-extracted event CSVs, write JSON files (no Kafka):
```bash
source .venv/bin/activate
python3 event_watch.py --model models/rf_event_multiclass.joblib \
    --watch-dir /path/to/event-csvs --once --stix-dir ./stix-out
```
Live — watch a directory, publish to Kafka, exit after 60s idle:
```bash
python3 event_watch.py --model models/rf_event_multiclass.joblib \
    --watch-dir /tmp/mmt-events --idle-timeout 60 --kafka
```

## Retrain / evaluate
```bash
python3 event_pipeline.py eval  --multiclass --data-dir /path/to/event-csvs
python3 event_pipeline.py train --multiclass --data-dir /path/to/event-csvs \
    --out models/rf_event_multiclass.joblib
```

## Model summary
- RandomForest (`n_estimators=300`, `class_weight="balanced"`); artifact stores
  `{model, feature_cols, classes, multiclass}`.
- Trained on 264 free5GC captures; leave-one-capture-out CV: 100% per-class F1.
- Pickled with: Python 3.13, scikit-learn 1.9.0, numpy 2.4.6, pandas 3.0.3, joblib 1.5.3
  (load with the same major versions).
