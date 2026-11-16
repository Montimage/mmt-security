"""Publish 5G NAS-replay alerts as STIX 2.1 bundles to Kafka over SASL_PLAINTEXT.

The bundle follows the format mmt-probe emits from src/modules/output_format/stix_format.c
(branch intact-new-features, after PR #23 / #25), so a consumer already parsing mmt-probe STIX
alerts needs no change: identity (MMT-Probe <probe-id>) / observed-data / address SCOs /
x-attack-type, deterministic ids, priority + verdict + rule_type in x-attack-type-ext, no
placeholder URL or simulation marker, valid STIX 2.1. The ML scorer adds one extension,
`x-mmt-features-ext` (the model's input datapoint), on observed-data.

Difference in provenance only: here the detection comes from the ML scorer
(event_watch.py), not from a mmt-security rule inside the probe.

Kafka settings mirror mmt-probe.conf's `kafka-output` block: when a username is set we
connect with security.protocol=SASL_PLAINTEXT and sasl.mechanism=PLAIN, otherwise plain
PLAINTEXT. Credentials are read from the `.env` file sitting beside this script (see
load_dotenv below) — that is the ONLY place you should have to edit. Either python client works:
    pip install confluent-kafka     # preferred: same librdkafka the probe uses
    pip install kafka-python        # pure-python fallback (no compiler needed)

Quick connectivity test WITHOUT any 5G traffic (sends one dummy bundle):
    python stix_kafka.py --test --kafka-broker HOST:PORT --kafka-topic TOPIC \
        --kafka-username USER --kafka-password PASS
"""

import argparse
import hashlib
import ipaddress
import json
import os
import time
import uuid


def load_dotenv(path=None):
    """Minimal .env reader — avoids a python-dotenv dependency on the VM.

    Reads KEY=value lines (# comments and optional surrounding quotes allowed) and puts
    them in os.environ WITHOUT overwriting variables already set for real, so an explicit
    `export MMT_KAFKA_PASSWORD=...` still beats the file. Returns the file used, or None.

    Looked up in order: $MMT_ENV_FILE, .env beside this script, .env in the cwd.
    """
    for p in ([path] if path else [os.environ.get("MMT_ENV_FILE"),
                                   os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
                                   os.path.join(os.getcwd(), ".env")]):
        if not p or not os.path.isfile(p):
            continue
        with open(p) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                    val = val[1:-1]          # strip optional quotes around the value
                os.environ.setdefault(key, val)
        return p
    return None


DOTENV_PATH = load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# ####  KAFKA SETTINGS — EDIT THE .env FILE, NOT THIS BLOCK  ####
# Resolution order (first one wins):
#   event_watch.py CLI flag  >  real environment variable  >  .env file  >  default below
# ─────────────────────────────────────────────────────────────────────────────
KAFKA_BROKER = os.environ.get("MMT_KAFKA_BROKER", "localhost:9092")   # "hostname:port"
KAFKA_TOPIC = os.environ.get("MMT_KAFKA_TOPIC", "report")             # topic to publish to
KAFKA_USERNAME = os.environ.get("MMT_KAFKA_USERNAME", "")             # empty = no auth (PLAINTEXT)
KAFKA_PASSWORD = os.environ.get("MMT_KAFKA_PASSWORD", "")             # SASL password
# Overrides for brokers that don't match mmt-probe's assumption of SASL_PLAINTEXT + PLAIN:
#   MMT_KAFKA_SECURITY_PROTOCOL = SASL_SSL / PLAINTEXT / ...   (empty = auto)
#   MMT_KAFKA_SASL_MECHANISM    = SCRAM-SHA-256 / SCRAM-SHA-512 / ...
KAFKA_SECURITY_PROTOCOL = os.environ.get("MMT_KAFKA_SECURITY_PROTOCOL", "")
KAFKA_SASL_MECHANISM = os.environ.get("MMT_KAFKA_SASL_MECHANISM", "PLAIN")
# Seconds close() waits for the broker to acknowledge queued bundles before giving up.
KAFKA_FLUSH_TIMEOUT = float(os.environ.get("MMT_KAFKA_FLUSH_TIMEOUT", "15"))
# librdkafka debug topics, e.g. "broker,security" — the fastest way to diagnose SASL.
KAFKA_DEBUG = os.environ.get("MMT_KAFKA_DEBUG", "")

# ── STIX fields — mirror mmt-probe `intact-new-features` (stix_format.c, PR #23 / #25) ──
# The producer identity is `probe-id` + `input-source`. By default both are read from the
# event-report window itself (its CSV columns 1 and 2 ARE the probe's probe-id and input
# source), so the identity of an ML alert is byte-identical to the probe's own identity object.
# Set these only to override.
STIX_PROBE_ID = os.environ.get("MMT_STIX_PROBE_ID", "")           # integer; empty = from the window
STIX_INPUT_SOURCE = os.environ.get("MMT_STIX_INPUT_SOURCE", "")   # empty = from the window
# external_id of the x-attack-type object = the mmt-security rule id that launches us.
STIX_RULE_ID = os.environ.get("MMT_STIX_RULE_ID", "500")
# Name put in the x-attack-type object. Empty (the default) = the attack class name derived
# from the traffic, e.g. "NAS Replay Attack". Set it to pin a fixed taxonomy label instead.
STIX_ATTACK_NAME = os.environ.get("MMT_STIX_ATTACK_NAME", "")
# x-attack-type-ext.{verdict, rule_type, priority}: same meaning as in the probe's bundles.
STIX_VERDICT = "detected"
STIX_RULE_TYPE = os.environ.get("MMT_STIX_RULE_TYPE", "attack")
STIX_PRIORITY = os.environ.get("MMT_STIX_PRIORITY", "")   # empty = default from the rule type

# STIX 2.1 namespace for deterministic ids (spec section 2.9), as in stix_format.c.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# created/modified of the identity: a constant, so the identity object is identical in every
# bundle (STIX: same id + same modified = same object version). Same value as the probe.
IDENTITY_TIMESTAMP = "1970-01-01T00:00:00.000Z"
PRIORITIES = ("critical", "high", "medium", "low")


def _sha1_uuid(namespace, name, version):
    """RFC 4122 name-based (SHA-1) UUID = libuuid's uuid_generate_sha1(), with the given
    version bits. version=5 for namespaces and SCOs, version=4 for the bundle and SDOs
    (stix_format.c: generate_object_uuid() forces version 4 on the SHA-1 output)."""
    if isinstance(name, str):
        name = name.encode("utf-8")
    return uuid.UUID(bytes=hashlib.sha1(namespace.bytes + name).digest()[:16], version=version)


_warned_probe_id = False


def _probe_id(window_value):
    """Integer probe id: the MMT_STIX_PROBE_ID override if it is an integer, else the probe id
    read from the window, else 0. A non-integer override (e.g. the old "MMT-PROBE-1") is
    ignored with a one-time warning instead of failing the alert."""
    global _warned_probe_id
    if STIX_PROBE_ID:
        try:
            return int(STIX_PROBE_ID.strip())
        except ValueError:
            if not _warned_probe_id:
                print(f"  !! MMT_STIX_PROBE_ID={STIX_PROBE_ID!r} is not an integer (the probe id is "
                      f"numeric, e.g. 3); ignoring it and using the probe id of the window.", flush=True)
                _warned_probe_id = True
    try:
        return int(str(window_value).strip())
    except (TypeError, ValueError):
        return 0


def default_priority(rule_type):
    """alert_priority() in stix_format.c: attack -> high, test -> low, anything else -> medium."""
    return {"attack": "high", "test": "low"}.get(rule_type, "medium")


def _split_ts(ts):
    """(seconds, microseconds) of an epoch timestamp, like a struct timeval."""
    ts = time.time() if ts is None else float(ts)
    sec = int(ts)
    usec = int(round((ts - sec) * 1_000_000))
    if usec >= 1_000_000:
        sec, usec = sec + 1, usec - 1_000_000
    return sec, usec


def _iso8601(sec, usec, micro):
    """format_timeval_iso8601(): millisecond (created/modified) or microsecond
    (first/last_observed) precision, UTC."""
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec))
    return base + (f".{usec:06d}Z" if micro else f".{usec // 1000:03d}Z")


def _address_objects(values):
    """addr_add_ip() in stix_format.c: keep a value only if it parses as IPv4 (ipv4-addr) or
    IPv6 (ipv6-addr, canonical form); empty/invalid values are dropped, so no SCO carries an
    invalid value. One object per distinct address, ids are deterministic UUIDv5."""
    out, seen = [], set()
    for v in values:
        v = (v or "").strip()
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            continue
        typ, val = ("ipv4-addr", v) if ip.version == 4 else ("ipv6-addr", str(ip))
        if (typ, val) in seen or len(out) >= 16:
            continue
        seen.add((typ, val))
        sco = _sha1_uuid(STIX_NAMESPACE, '{"value":"%s"}' % val, 5)
        out.append({"type": typ, "spec_version": "2.1", "id": f"{typ}--{sco}", "value": val})
    return out


def build_stix_bundle(description, src_ip="", dst_ip="", rule_id=STIX_RULE_ID, ts=None,
                      attack_name=None, features=None, predicted_class=None, model_name=None,
                      probe_id=None, input_source=None, trace=None,
                      rule_type=None, verdict=None, priority=None):
    """Return the STIX 2.1 bundle (as a dict) for one alert, in the same format as
    construct_alert_stix_format() in mmt-probe (branch intact-new-features):

    identity (MMT-Probe <probe-id>) -> observed-data -> 0..16 address SCOs -> x-attack-type,
    deterministic ids, no `url` in external_references, no simulation marker, and
    priority / verdict / rule_type in x-attack-type-ext. The bundles pass stix2-validator (2.1).

    ML-specific on top of the probe format:
      * x-attack-type `name` is the predicted attack (e.g. "NAS Replay Attack");
        `description` keeps the numeric detail.
      * `features` (an ordered {feature_name: value} dict) — the exact input datapoint the model
        scored — is attached to observed-data as the `x-mmt-features-ext` extension, so an xAI tool
        (AVA) can explain this very prediction.

    `trace` plays the role of the probe's event trace in the alert key: the same alert (probe,
    time, rule, trace) always gives the same ids. Pass the alert time as `ts` (the scorer uses
    the last event of the window) to keep ids stable across re-runs.
    """
    attack_name = STIX_ATTACK_NAME or attack_name or description
    probe_id = _probe_id(probe_id)
    input_source = STIX_INPUT_SOURCE or input_source or ""
    rule_id = str(rule_id)
    rule_type = rule_type or STIX_RULE_TYPE
    verdict = verdict or STIX_VERDICT
    priority = (priority or STIX_PRIORITY or default_priority(rule_type)).lower()
    if priority not in PRIORITIES:
        priority = default_priority(rule_type)
    if trace is None:
        trace = json.dumps({"description": description, "features": features},
                           sort_keys=True, separators=(",", ":"))

    sec, usec = _split_ts(ts)
    stamp, observed = _iso8601(sec, usec, False), _iso8601(sec, usec, True)

    # ids — alert_namespace() / probe_namespace() / generate_object_uuid() in stix_format.c
    alert_ns = _sha1_uuid(STIX_NAMESPACE, f"mmt-probe|{probe_id}|{sec}.{usec:06d}|{rule_id}|{trace}", 5)
    probe_ns = _sha1_uuid(STIX_NAMESPACE, f"mmt-probe|{probe_id}|{input_source}", 5)
    bundle_id = _sha1_uuid(alert_ns, "bundle", 4)
    identity_id = _sha1_uuid(probe_ns, "identity", 4)
    observed_id = _sha1_uuid(alert_ns, "observed-data", 4)
    attack_id = _sha1_uuid(alert_ns, "x-attack-type", 4)

    addrs = _address_objects([src_ip, dst_ip])

    observed_ext = {
        "x-observed-data-ext": {
            "extension_type": "property-extension",
            "description": description,
        }
    }
    if features is not None:
        # The ML input datapoint, so AVA can initialise an xAI task on it. feature_names gives
        # the column order explicitly; feature_values is the aligned vector; features is the
        # same as a name:value map for convenience.
        observed_ext["x-mmt-features-ext"] = {
            "extension_type": "property-extension",
            "model": model_name or "rf_event_multiclass",
            "predicted_class": predicted_class,
            "feature_names": list(features.keys()),
            "feature_values": [features[k] for k in features],
            "features": dict(features),
        }

    return {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": f"identity--{identity_id}",
                "created": IDENTITY_TIMESTAMP,
                "modified": IDENTITY_TIMESTAMP,
                "name": f"MMT-Probe {probe_id}",
                "identity_class": "system",
                "extensions": {
                    "x-probe-id-ext": {
                        "extension_type": "property-extension",
                        "probe-id": probe_id,
                        "input-source": input_source,
                    }
                },
            },
            {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{observed_id}",
                "created": stamp,
                "modified": stamp,
                "first_observed": observed,
                "last_observed": observed,
                "number_observed": 1,
                "object_refs": [a["id"] for a in addrs] + [f"x-attack-type--{attack_id}"],
                "created_by_ref": f"identity--{identity_id}",
                "extensions": observed_ext,
            },
            *addrs,
            {
                "type": "x-attack-type",
                "id": f"x-attack-type--{attack_id}",
                "name": attack_name or f"mmt-security rule {rule_id}",
                "created": stamp,
                "modified": stamp,
                "extensions": {
                    "x-attack-type-ext": {
                        "extension_type": "new-sdo",
                        "priority": priority,
                        "verdict": verdict,
                        "rule_type": rule_type,
                    }
                },
                "external_references": [
                    {"source_name": "mmt-security", "external_id": rule_id}
                ],
            },
        ],
    }


def serialize(bundle):
    """The exact bytes published to Kafka. Used for the file sinks too, so what you
    inspect offline is byte-for-byte what a consumer would receive."""
    return json.dumps(bundle, indent=2)


class KafkaStixSender:
    """Publishes STIX bundles to Kafka. Never raises into the caller: a broker that is
    down must not stop the scorer from writing its normal file/stdout alerts."""

    def __init__(self, broker, topic, username="", password="", log=print):
        self.broker, self.topic, self.log = broker, topic, log
        self.username, self.password = username, password
        self.backend = self._producer = None
        self.n_queued = self.n_delivered = self.n_failed = 0
        self._connect()

    # ---- callbacks: without these, produce() failures are invisible ----------------
    def _on_delivery(self, err, msg):
        """Called once per message when the broker acks it (or gives up)."""
        if err is not None:
            self.n_failed += 1
            self.log(f"  !! kafka DELIVERY FAILED: {err}")
        else:
            self.n_delivered += 1
            self.log(f"  -> STIX bundle DELIVERED to {msg.topic()}[{msg.partition()}] "
                     f"offset {msg.offset()}")

    def _on_error(self, err):
        """Broker-level errors: bad credentials, unreachable host, unknown topic."""
        self.log(f"  !! kafka error: {err}")

    def _connect(self):
        # security.protocol follows mmt-probe (SASL_PLAINTEXT iff a username is given)
        # unless MMT_KAFKA_SECURITY_PROTOCOL overrides it.
        use_sasl = bool(self.username)
        protocol = KAFKA_SECURITY_PROTOCOL or ("SASL_PLAINTEXT" if use_sasl else "PLAINTEXT")
        try:
            from confluent_kafka import Producer  # same librdkafka the probe links against
            conf = {"bootstrap.servers": self.broker,
                    "security.protocol": protocol,
                    "error_cb": self._on_error,
                    # Fail loudly and quickly rather than hanging on a dead broker.
                    "socket.timeout.ms": 10000,
                    "message.timeout.ms": int(os.environ.get("MMT_KAFKA_MESSAGE_TIMEOUT_MS", "30000"))}
            # librdkafka defaults to acks=all. Set MMT_KAFKA_ACKS=1 to require only the
            # leader's ack — the fix when the topic has fewer in-sync replicas than the
            # broker's min.insync.replicas demands.
            if os.environ.get("MMT_KAFKA_ACKS"):
                conf["acks"] = os.environ["MMT_KAFKA_ACKS"]
            if use_sasl:
                conf.update({"sasl.mechanism": KAFKA_SASL_MECHANISM,
                             "sasl.username": self.username,
                             "sasl.password": self.password})
            if KAFKA_DEBUG:
                conf["debug"] = KAFKA_DEBUG
            self._producer, self.backend = Producer(conf), "confluent-kafka"
        except ImportError:
            try:
                from kafka import KafkaProducer
                kw = {"bootstrap_servers": self.broker.split(","),
                      "security_protocol": protocol,
                      "value_serializer": lambda v: v.encode()}
                if use_sasl:
                    kw.update({"sasl_mechanism": KAFKA_SASL_MECHANISM,
                               "sasl_plain_username": self.username,
                               "sasl_plain_password": self.password})
                self._producer, self.backend = KafkaProducer(**kw), "kafka-python"
            except ImportError:
                self.log("  !! no kafka client installed (pip install confluent-kafka OR "
                         "kafka-python); STIX alerts will NOT be published.")
                return
        except Exception as e:
            self.log(f"  !! kafka producer init failed ({e}); STIX alerts will NOT be published.")
            return
        self.log(f"STIX->Kafka via {self.backend}: {self.broker} topic='{self.topic}' "
                 f"protocol={protocol}" + (f" (config from {DOTENV_PATH})" if DOTENV_PATH else ""))

    def send(self, bundle):
        """QUEUE one bundle for delivery. Returns True if it was accepted by the producer —
        NOT that the broker got it. Actual delivery is reported by _on_delivery(), and
        close() waits for it; check n_delivered / n_failed for the verdict."""
        if self._producer is None:
            return False
        payload = serialize(bundle)
        try:
            if self.backend == "confluent-kafka":
                self._producer.produce(self.topic, payload.encode(), callback=self._on_delivery)
                self._producer.poll(0)          # serve delivery callbacks, non-blocking
            else:
                (self._producer.send(self.topic, payload)
                 .add_callback(lambda md: self._on_delivery(None, md))
                 .add_errback(lambda e: self._on_delivery(e, None)))
            self.n_queued += 1
            return True
        except Exception as e:
            self.log(f"  !! kafka send failed: {e}")
            self.n_failed += 1
            return False

    def poll(self):
        """Serve pending delivery callbacks (non-blocking). Safe to call every loop tick."""
        if self._producer is not None and self.backend == "confluent-kafka":
            try:
                self._producer.poll(0)
            except Exception:
                pass

    def close(self, timeout=None):
        """Wait for the broker to acknowledge every queued bundle, then report the tally.

        This is what stops a bundle from being lost when the scorer self-terminates: a
        non-zero remainder here means the messages never reached Kafka, so say so loudly
        instead of exiting quietly (which is how a silent drop went unnoticed before).
        """
        if self._producer is None:
            return
        timeout = KAFKA_FLUSH_TIMEOUT if timeout is None else timeout
        remaining = None
        try:
            remaining = self._producer.flush(timeout)
        except Exception as e:
            self.log(f"  !! kafka flush failed: {e}")
        if remaining:
            self.log(f"  !! KAFKA DELIVERY INCOMPLETE: {remaining} bundle(s) still queued after "
                     f"{timeout:.0f}s — they were NOT published.")
        if self.n_queued:
            self.log(f"Kafka summary: {self.n_queued} queued, {self.n_delivered} delivered, "
                     f"{self.n_failed} failed.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", action="store_true", help="send one dummy bundle to check connectivity")
    ap.add_argument("--print", dest="show", action="store_true", help="print the dummy bundle and exit")
    ap.add_argument("--kafka-broker", default=KAFKA_BROKER)
    ap.add_argument("--kafka-topic", default=KAFKA_TOPIC)
    ap.add_argument("--kafka-username", default=KAFKA_USERNAME)
    ap.add_argument("--kafka-password", default=KAFKA_PASSWORD)
    args = ap.parse_args()

    bundle = build_stix_bundle(
        "TEST 5G NAS-replay alert from event_watch.py (connectivity check)",
        src_ip="10.100.200.1", dst_ip="10.100.200.16")
    if args.show or not args.test:
        print(json.dumps(bundle, indent=2))
        if not args.test:
            return
    sender = KafkaStixSender(args.kafka_broker, args.kafka_topic,
                             args.kafka_username, args.kafka_password)
    sender.send(bundle)
    sender.close()          # waits for the broker's ack and prints the tally
    # The verdict is delivery, not enqueue: queueing always "works".
    if sender.n_delivered:
        print(f"RESULT: delivered to topic '{args.kafka_topic}' — the channel works.")
    else:
        print(f"RESULT: NOT delivered to topic '{args.kafka_topic}'. The bundle never reached "
              f"the broker — see the error above.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
