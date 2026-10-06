"""Parse NGAP/NAS event reports (mmt-probe format id = 1000) and build ONE core-invariant
feature vector per capture, for the portable replay detector.

Row layout written by pcap-to-csv/extract_event.sh (event-report 'ngap_nas'):
  0 report_type(=1000)  1 probe_id  2 source  3 report_time  4 title  5 event_value
  then the attributes IN THIS EXACT ORDER (must match the .conf attributes list):
  6 ip.src  7 ip.dst  8 sctp.src_port  9 sctp.dest_port  10 sctp.verif_tag
  11 ngap.procedure_code  12 ngap.pdu_present  13 ngap.amf_ue_id  14 ngap.ran_ue_id
  15 nas_5g.message_type  16 nas_5g.security_type  17 nas_5g.sequence_number
  18 nas_5g.message_authentication_code

Why these features transfer across cores: NGAP procedure codes and NAS message types are
3GPP-standardized (same integers on free5GC / Open5GS / OAI / commercial), and the NAS
message-authentication-code is a cryptographic value — a byte-replayed NAS message repeats
the identical MAC, which essentially never happens in legitimate traffic. So "duplicate
MAC" is a near-definitive, core-independent replay signal.
"""

import csv
import glob
import os

import numpy as np
import pandas as pd

REPORT_TYPE_EVENT = "1000"
N_FIXED = 6  # report_type, probe_id, source, report_time, title, event_value
TITLE_IDX = 4                 # CSV field 4 = event-report NAME (e.g. "ngap_nas" / "sctp_data")
REPORT_NGAP = "ngap_nas"      # names must match the event-report blocks in extract_event.sh
REPORT_SCTP = "sctp_data"

ATTR_COLS = [
    "ip_src", "ip_dst", "sctp_src_port", "sctp_dest_port", "sctp_verif_tag",
    "ngap_procedure_code", "ngap_pdu_present", "ngap_amf_ue_id", "ngap_ran_ue_id",
    "nas_message_type", "nas_security_type", "nas_sequence_number", "nas_mac",
    "sctp_data_ppid",
]
# Attributes added AFTER the first datasets were extracted. They live at the END of
# ATTR_COLS, so CSVs produced before they existed are still readable (padded with 0).
OPTIONAL_ATTR_COLS = ["sctp_data_ppid"]

# Layout of the SECOND report (sctp_data) from extract_event.sh: one row per SCTP DATA chunk.
SCTP_ATTR_COLS = [
    "ip_src", "ip_dst", "sctp_src_port", "sctp_dest_port", "sctp_verif_tag",
    "sctp_data_ppid", "ngap_procedure_code", "nas_mac",
]
_NUM_ATTRS = [
    "sctp_src_port", "sctp_dest_port",
    "ngap_procedure_code", "ngap_pdu_present", "ngap_amf_ue_id", "ngap_ran_ue_id",
    "nas_message_type", "nas_security_type", "nas_sequence_number",
    "sctp_data_ppid",
]

# 5GMM message type of the message 5Greplay's rule 4 replays (TS 24.501 Table 9.7.1.1).
# 0x5D = 93 = Security mode COMMAND (the AMF's downlink message, re-sent at the AMF).
# NOTE: the old name/comment here said "Security Mode Complete"; that was a mislabel —
# the value 93 (and therefore every feature) is unchanged, only the wording is corrected.
NAS_SECURITY_MODE_COMMAND = 93
NAS_SMC_COMPLETE = NAS_SECURITY_MODE_COMMAND   # kept so older scripts importing this name still work

# 5GMM message types (TS 24.501 Table 9.7.1.1), used to NAME the replayed message in an
# alert instead of hard-coding one attack label.
NAS_MSG_NAMES = {
    65: "Registration Request", 66: "Registration Accept",
    67: "Registration Complete", 68: "Registration Reject",
    69: "Deregistration Request (UE originating)", 70: "Deregistration Accept (UE originating)",
    71: "Deregistration Request (UE terminated)", 72: "Deregistration Accept (UE terminated)",
    76: "Service Request", 77: "Service Reject", 78: "Service Accept",
    84: "Configuration Update Command", 85: "Configuration Update Complete",
    86: "Authentication Request", 87: "Authentication Response",
    88: "Authentication Reject", 89: "Authentication Failure", 90: "Authentication Result",
    91: "Identity Request", 92: "Identity Response",
    93: "Security Mode Command", 94: "Security Mode Complete", 95: "Security Mode Reject",
    100: "5GMM Status", 101: "Notification", 102: "Notification Response",
    103: "UL NAS Transport", 104: "DL NAS Transport",
}


def nas_msg_name(msg_type):
    """Human name of a 5GMM message type, or 'NAS message type <n>' when unknown."""
    try:
        msg_type = int(msg_type)
    except (TypeError, ValueError):
        return "unknown NAS message"
    return NAS_MSG_NAMES.get(msg_type, f"NAS message type {msg_type}")


def describe_replay(df, mac=None):
    """Identify the replayed message from the DATA rather than assuming it.

    Returns a dict describing the duplicated-MAC leg: which MAC repeated, how often, the
    5GMM message type(s) carried, their names, and the endpoints. Everything an alert
    needs is derived from the window CSV, so a replay of a different NAS message is
    reported as that message instead of a fixed 'SMC replay' label.
    """
    nas = df[df["nas_message_type"] != 0]
    prot = nas[(nas["nas_security_type"] != 0) & (~nas["nas_mac"].isin(["", "0"]))]
    if len(prot) == 0:
        return {"mac": None, "mult": 0, "msg_types": [], "msg_names": [],
                "label": "NAS replay", "src_ip": "", "dst_ip": ""}
    if mac is None:
        mac = prot["nas_mac"].value_counts().index[0]
    rows = prot[prot["nas_mac"] == mac]
    if rows.empty:
        rows = prot
    types = [int(t) for t in rows["nas_message_type"].value_counts().index.tolist()]
    names = [nas_msg_name(t) for t in types]

    def _top(col):
        vals = rows[col][rows[col].astype(str) != ""]
        return str(vals.value_counts().index[0]) if len(vals) else ""

    return {
        "mac": mac,
        "mult": int(len(rows)),
        "msg_types": types,
        "msg_names": names,
        # e.g. "NAS Security Mode Command replay" — derived, not hard-coded.
        "label": f"NAS {names[0]} replay" if names else "NAS replay",
        "src_ip": _top("ip_src"),
        "dst_ip": _top("ip_dst"),
    }

# Feature columns fed to the model. All are ratios / standardized-enum counts, chosen to be
# core-invariant (no raw byte volumes). n_msgs / n_nas are carried for reporting only.
FEATURE_COLS = [
    "dup_mac_ratio",       # frac of integrity-protected NAS msgs whose MAC is duplicated  <-- key signal
    "max_mac_mult",        # largest count of one identical MAC (how many replayed copies)
    "dup_seq_ratio",       # frac of protected NAS msgs whose sequence_number is duplicated
    "max_ranue_spread",    # max # of distinct SCTP associations a single RAN-UE-NGAP-ID appears on
    "n_verif_tags",        # # of distinct SCTP associations
    "frac_smc",            # frac of NAS msgs that are Security Mode Complete
    "frac_prot",           # frac of NAS msgs that are integrity-protected
    "n_distinct_msgtype",  # # of distinct NAS message types seen
    "n_distinct_proc",     # # of distinct NGAP procedure codes seen
]
LABEL_COL = "label"
GROUP_COL = "pcap"
AMF_SCTP_PORT = 38412   # N2 (NGAP) SCTP port; sctp_data rows to this port go UE/gNB -> AMF

# Extra features for the MULTI-CLASS model (replay / flooding / malformed / normal).
# They add three separating axes the binary features lacked:
#   dup_concentration + n_dup_macs  -> replay (one MAC) vs flooding (many MACs)
#   frac_no_ngap + n_sctp_data      -> malformed (SCTP DATA that doesn't parse as NGAP)
#   max_mac_mult_any                -> replay signal even when the message is ciphered
MULTICLASS_FEATURE_COLS = [
    "dup_mac_ratio_any", "max_mac_mult_any", "dup_concentration", "n_dup_macs",
    "frac_no_ngap", "n_sctp_data",
    "frac_smc", "frac_prot", "max_ranue_spread",
    "n_distinct_msgtype", "n_distinct_proc", "n_msgs",
]
# Union of every feature featurize_capture emits (used to zero-fill the base dict).
ALL_FEATURE_COLS = list(dict.fromkeys(FEATURE_COLS + MULTICLASS_FEATURE_COLS))

# Multi-class labels, decided by the capture filename prefix (set by capture_*_free5gc.sh
# CTX_PREFIX). Order is the reported class order.
CLASSES = ["normal", "replay", "flooding", "malformed"]


def label_from_filename(path):
    """Binary label for the existing model: 1 = attack, 0 = normal."""
    return int(os.path.basename(path).lower().startswith("abnormal"))


def class_from_filename(path):
    """Multi-class label from the filename. Attack captures keep the CTX_PREFIX family keyword
    (replay/flooding/malformed) in the name; normal captures start with 'normal_'.

    Family keywords are matched FIRST — 'normal' is a substring of 'abnormal', so testing the
    attack families before the normal case avoids labelling every attack as normal.
    """
    name = os.path.basename(path).lower()
    if "flooding" in name:
        return "flooding"
    if "malformed" in name:
        return "malformed"
    if "replay" in name:        # covers 'replay' and the older 'smc_replay' prefix
        return "replay"
    return "normal"             # 'normal_*', 'nominal', anything with no attack keyword


def _read_report(path, report_name, attr_cols):
    """Rows of one named event report (CSV field 4 == report_name) as a DataFrame.

    A file with a SINGLE report predates the report-name split (all its 1000-rows are the
    ngap_nas report); those rows carry the name too, verified in the CSV, so filtering by name
    is safe for both old and new files. Trailing attributes missing from an older layout are
    padded with "0".
    """
    n_req = N_FIXED + len(attr_cols) - (len(OPTIONAL_ATTR_COLS) if report_name == REPORT_NGAP else 0)
    rows = []
    with open(path, newline="") as f:
        for fields in csv.reader(f):
            if not fields or fields[0] != REPORT_TYPE_EVENT:
                continue
            if len(fields) <= TITLE_IDX or fields[TITLE_IDX].strip().strip('"') != report_name:
                continue
            if len(fields) < n_req:
                continue
            attrs = fields[N_FIXED:N_FIXED + len(attr_cols)]
            attrs += ["0"] * (len(attr_cols) - len(attrs))
            rows.append(attrs)
    return pd.DataFrame(rows, columns=attr_cols)


def load_event_file(path):
    """Return a DataFrame with one row per parsed NGAP message (the ngap_nas report).

    Backward compatible: files written before the report-name split still carry "ngap_nas"
    in field 4, and files with only 13 attributes get sctp_data_ppid padded to 0.
    """
    df = _read_report(path, REPORT_NGAP, ATTR_COLS)
    for c in _NUM_ATTRS:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(np.int64)
    for c in ("sctp_verif_tag", "nas_mac", "ip_src", "ip_dst"):
        df[c] = df[c].astype(str).str.strip().str.strip('"')
    return df


def load_sctp_file(path):
    """Return the sctp_data report (one row per SCTP DATA chunk). Empty for old CSVs that
    never had this second report — callers then treat n_sctp_data as 0."""
    df = _read_report(path, REPORT_SCTP, SCTP_ATTR_COLS)
    for c in ("sctp_src_port", "sctp_dest_port", "sctp_data_ppid", "ngap_procedure_code"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(np.int64)
    for c in ("nas_mac", "ip_src", "ip_dst"):
        df[c] = df[c].astype(str).str.strip().str.strip('"')
    return df


def featurize_capture(df, sctp_df=None):
    """Aggregate one capture into a feature dict.

    Returns BOTH the original 9 features (unchanged semantics, so the existing binary model
    keeps working) AND the extra multi-class features. Each model selects its own columns via
    its saved feature_cols, so the two coexist.

    `sctp_df` (the sctp_data report) is optional; without it the malformed-only features are 0,
    which is correct for pre-second-report CSVs.
    """
    n_msgs = len(df)
    base = {c: 0.0 for c in ALL_FEATURE_COLS} | {"n_msgs": n_msgs, "n_nas": 0}
    if n_msgs == 0 and (sctp_df is None or len(sctp_df) == 0):
        return base

    nas = df[df["nas_message_type"] != 0]
    n_nas = len(nas)
    prot = nas[(nas["nas_security_type"] != 0) & (~nas["nas_mac"].isin(["", "0"]))]

    # --- original dup-MAC, computed on readable-NAS rows (unchanged) ---
    if len(prot):
        mac_counts = prot["nas_mac"].value_counts()
        dup_mac_ratio = float(mac_counts[mac_counts > 1].sum()) / len(prot)
        max_mac_mult = int(mac_counts.max())
        seq_counts = prot["nas_sequence_number"].value_counts()
        dup_seq_ratio = float(seq_counts[seq_counts > 1].sum()) / len(prot)
    else:
        dup_mac_ratio = dup_seq_ratio = 0.0
        max_mac_mult = 0

    # --- dup-MAC on ANY row carrying a MAC, message_type IGNORED. Catches the CIPHERED SMC
    #     Complete replay (message_type unreadable, MAC in the plaintext security header). ---
    macs = df[~df["nas_mac"].isin(["", "0"])] if n_msgs else df.iloc[0:0]
    if len(macs):
        amc = macs["nas_mac"].value_counts()
        dup_occ = int(amc[amc > 1].sum())               # rows that are part of some duplicate
        max_mac_mult_any = int(amc.iloc[0])
        dup_mac_ratio_any = dup_occ / len(macs)
        n_dup_macs = int((amc > 1).sum())               # replay -> 1, flooding -> several
        # share of duplicate occurrences held by the single most-repeated MAC:
        # replay concentrates on ONE MAC (~1.0); flooding spreads across many (<1.0).
        dup_concentration = (max_mac_mult_any / dup_occ) if dup_occ else 0.0
    else:
        max_mac_mult_any = n_dup_macs = 0
        dup_mac_ratio_any = dup_concentration = 0.0

    nz = df[df["ngap_ran_ue_id"] != 0]
    max_ranue_spread = int(nz.groupby("ngap_ran_ue_id")["sctp_verif_tag"].nunique().max()) if len(nz) else 0
    frac_smc = float((nas["nas_message_type"] == NAS_SMC_COMPLETE).mean()) if n_nas else 0.0
    frac_prot = len(prot) / n_nas if n_nas else 0.0

    # --- malformed signal: SCTP DATA chunks to the AMF that yielded NO valid NGAP parse ---
    n_sctp_data = frac_no_ngap = 0.0
    if sctp_df is not None and len(sctp_df):
        to_core = sctp_df[sctp_df["sctp_dest_port"] == AMF_SCTP_PORT]
        base_rows = to_core if len(to_core) else sctp_df
        n_sctp_data = len(base_rows)
        frac_no_ngap = float((base_rows["ngap_procedure_code"] == 0).mean())

    return base | {
        "dup_mac_ratio": dup_mac_ratio,
        "max_mac_mult": max_mac_mult,
        "dup_seq_ratio": dup_seq_ratio,
        "max_ranue_spread": max_ranue_spread,
        "n_verif_tags": int(df["sctp_verif_tag"].nunique()) if n_msgs else 0,
        "frac_smc": frac_smc,
        "frac_prot": frac_prot,
        "n_distinct_msgtype": int(nas["nas_message_type"].nunique()) if n_nas else 0,
        "n_distinct_proc": int(df[df["ngap_procedure_code"] != 0]["ngap_procedure_code"].nunique()) if n_msgs else 0,
        "max_mac_mult_any": max_mac_mult_any,
        "dup_mac_ratio_any": dup_mac_ratio_any,
        "n_dup_macs": n_dup_macs,
        "dup_concentration": dup_concentration,
        "frac_no_ngap": frac_no_ngap,
        "n_sctp_data": n_sctp_data,
        "n_msgs": n_msgs,
        "n_nas": n_nas,
    }


def load_event_dataset(data_dir, multiclass=False):
    """One row per capture: features + label + group + row counts.

    multiclass=False -> LABEL_COL is the binary 0/1 (existing behaviour).
    multiclass=True  -> LABEL_COL is the class string (normal/replay/flooding/malformed) and
                        the sctp_data report is read so the malformed features are populated.
    """
    files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSVs in {data_dir}")
    recs = []
    for p in files:
        sctp_df = load_sctp_file(p) if multiclass else None
        feat = featurize_capture(load_event_file(p), sctp_df)
        feat[GROUP_COL] = os.path.splitext(os.path.basename(p))[0]
        feat[LABEL_COL] = class_from_filename(p) if multiclass else label_from_filename(p)
        recs.append(feat)
    df = pd.DataFrame(recs)
    if multiclass:
        counts = df[LABEL_COL].value_counts().to_dict()
        print(f"Loaded {len(files)} capture(s) from {data_dir}  classes: {counts}")
    else:
        print(f"Loaded {len(files)} capture(s) from {data_dir}  "
              f"({int(df[LABEL_COL].sum())} abnormal, {int((df[LABEL_COL] == 0).sum())} normal)")
    return df


def rule_prediction(df, min_mult=3):
    """Portable rule baseline: a capture is an (amplified) replay if some integrity-protected
    NAS message appears byte-identical (same MAC) at least `min_mult` times.

    Threshold is 3, not 2, on purpose: a legitimate SCTP retransmission repeats one NAS
    message exactly once (multiplicity 2), whereas a real replay amplifies it many times
    (nb_copies >= 10 here). So >=3 rejects retransmissions while keeping every amplified
    replay. It cannot catch a single-shot (nb_copies=1) replay, which leaves no duplicate at
    all -- that case needs stateful security-context validation, not per-capture statistics."""
    return (df["max_mac_mult"] >= min_mult).astype(int)
