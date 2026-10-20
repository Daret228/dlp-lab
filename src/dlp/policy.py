import hashlib
import math
import re
from pathlib import Path
import yaml
from .models import Decision
from .file_types import SUPPORTED_TYPES


class PolicyError(ValueError):
    pass


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise PolicyError("Mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def keys(value, required):
    if not isinstance(value, dict) or set(value) != set(required):
        raise PolicyError(f"Expected exactly these keys: {required}")


def number(value, minimum=0, maximum=float("inf")):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError("Expected number")
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise PolicyError("Number out of range")
    return value


def load_policy(path: str | Path) -> dict:
    return load_policy_snapshot(path)[0]


def load_policy_snapshot(path: str | Path):
    # Parse and hash the very same bounded read, even if the path is replaced later.
    with Path(path).open('rb') as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise PolicyError("Policy exceeds 256 KiB")
    return parse_policy(raw), hashlib.sha256(raw).hexdigest()


def parse_policy(raw):
    try:
        p = yaml.load(raw.decode('utf-8'), Loader=StrictLoader)
        required = ("version", "thresholds", "weights", "limits", "on_error", "rules")
        keys(p, required + tuple(k for k in ("file_types", "sensitive_alerts", "ml_alerts") if isinstance(p, dict) and k in p))
        if "ml_alerts" in p:
            cfg = p["ml_alerts"]
            keys(cfg, ("enabled", "action", "model_sha256"))
            if (type(cfg["enabled"]) is not bool or cfg["action"] != "WARN"
                    or not isinstance(cfg["model_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", cfg["model_sha256"])):
                raise PolicyError("ML requires boolean enabled, WARN and model SHA256")
        if "sensitive_alerts" in p:
            cfg = p["sensitive_alerts"]
            keys(cfg, ("enabled", "mode", "action"))
            if type(cfg["enabled"]) is not bool or cfg["mode"] != "rules" or cfg["action"] != "WARN":
                raise PolicyError("sensitive_alerts supports boolean enabled, mode rules, action WARN only")
        if "file_types" in p:
            file_types = p["file_types"]
            keys(file_types, ("allow", "deny"))
            for name in ("allow", "deny"):
                values = file_types[name]
                if (not isinstance(values, list)
                        or not all(isinstance(v, str) and v in SUPPORTED_TYPES for v in values)
                        or len(set(values)) != len(values)):
                    raise PolicyError("Invalid file type list")
            if set(file_types["allow"]) & set(file_types["deny"]):
                raise PolicyError("File type cannot be both allowed and denied")
        keys(p["thresholds"], ("warn", "block"))
        keys(p["weights"], ("dictionary", "regex", "context"))
        keys(p["limits"], ("max_bytes", "timeout_seconds"))
        if type(p["version"]) is not int or p["version"] != 1:
            raise PolicyError("Unsupported policy version")
        t = p["thresholds"]
        if not 0 <= number(t["warn"]) < number(t["block"]):
            raise PolicyError("Expected 0 <= warn < block")
        for kind in ("dictionary", "regex", "context"):
            number(p["weights"][kind])
        n = p["limits"]["max_bytes"]
        if type(n) is not int or not 1 <= n <= 16 * 1024 * 1024:
            raise PolicyError("max_bytes must be 1..16777216")
        number(p["limits"]["timeout_seconds"], 0.01, 30)
        Decision(p["on_error"])
        if not isinstance(p["rules"], list) or len(p["rules"]) > 1000:
            raise PolicyError("Expected at most 1000 rules")
        ids = set()
        for r in p["rules"]:
            if not isinstance(r, dict):
                raise PolicyError("Rule must be a mapping")
            fields = {"regex": ["pattern"], "dictionary": ["terms"], "context": ["terms", "context", "window"]}
            if r.get("type") not in fields:
                raise PolicyError("Unknown analyzer")
            keys(r, ["id", "type", "category", "severity"] + fields[r["type"]])
            if not isinstance(r["id"], str) or not r["id"] or r["id"] in ids:
                raise PolicyError("Rule IDs must be nonempty and unique")
            ids.add(r["id"])
            if r["type"] not in ("dictionary", "regex", "context"):
                raise PolicyError("Unknown analyzer")
            number(r["severity"], 0, 1)
            if not isinstance(r["category"], str):
                raise PolicyError("Invalid category")
            if r["type"] == "regex":
                if not isinstance(r["pattern"], str) or not r["pattern"]:
                    raise PolicyError("Empty regex")
                re.compile(r["pattern"])
            else:
                for key in (["terms", "context"] if r["type"] == "context" else ["terms"]):
                    if not isinstance(r[key], list) or not r[key] or not all(isinstance(x, str) and x for x in r[key]):
                        raise PolicyError("Expected nonempty terms")
                if r["type"] == "context" and (type(r["window"]) is not int or not 0 <= r["window"] <= 10000):
                    raise PolicyError("Invalid context window")
        return p
    except (KeyError, TypeError, ValueError, re.error, yaml.YAMLError, RecursionError) as exc:
        raise PolicyError(f"Invalid policy: {exc}") from exc


class PolicyEngine:
    def __init__(self, policy):
        self.policy = policy

    def decide(self, findings):
        # Each rule contributes once; repeating a word cannot inflate the score.
        by_rule = {}
        for f in findings:
            contribution = self.policy["weights"].get(f.analyzer, 0) * f.severity * f.confidence
            by_rule[f.rule_id] = max(by_rule.get(f.rule_id, 0), contribution)
        score = sum(by_rule.values())
        thresholds = self.policy["thresholds"]
        decision = Decision.BLOCK if score >= thresholds["block"] else Decision.WARN if score >= thresholds["warn"] else Decision.ALLOW
        return score, decision
