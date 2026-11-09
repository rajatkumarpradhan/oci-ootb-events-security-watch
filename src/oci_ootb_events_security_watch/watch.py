"""Coverage checking for OCI Events security-notification rules.

OCI Events is the built-in OCI feature that reacts to resource changes; the
standard security posture is a set of event rules that notify a topic when
someone changes IAM policy, network security, bucket access, or credentials.
This module works on a static JSON list of rule definitions: it checks that
every security-relevant event type is covered by an enabled rule that
actually delivers somewhere. All analysis is offline; no OCI calls.
"""

from dataclasses import dataclass

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Security-relevant OCI event types that should page someone when they fire.
REQUIRED_EVENT_TYPES = {
    "com.oraclecloud.identitycontrolplane.createpolicy": "IAM policy created",
    "com.oraclecloud.identitycontrolplane.updatepolicy": "IAM policy changed",
    "com.oraclecloud.identitycontrolplane.createapikey": "API key created",
    "com.oraclecloud.virtualnetwork.updatesecuritylist": "security list changed",
    "com.oraclecloud.objectstorage.updatebucket": "bucket settings changed (public access risk)",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    subject: str
    message: str


def _enabled_rules(document):
    rules = document.get("rules")
    if not isinstance(rules, list):
        raise ValueError("document must contain a top-level 'rules' list")
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("each rule entry must be an object")
        if not rule.get("name"):
            raise ValueError("rule entry missing 'name'")
        if not isinstance(rule.get("event_types"), list):
            raise ValueError(f"rule {rule.get('name')} missing 'event_types' list")
    return rules


def check_coverage(document):
    rules = _enabled_rules(document)
    findings = []

    covered = set()
    for rule in rules:
        if rule.get("enabled") is False:
            findings.append(Finding("WAT002", "MEDIUM", rule["name"], "rule is disabled; its event types are not being watched"))
        actions = rule.get("actions") or {}
        if not actions.get("topic"):
            findings.append(Finding("WAT003", "MEDIUM", rule["name"], "rule has no notification topic; matches would go nowhere"))

    active_types = set()
    for rule in rules:
        if rule.get("enabled") is False:
            continue
        if not (rule.get("actions") or {}).get("topic"):
            continue
        active_types.update(rule["event_types"])
        covered.update(rule["event_types"])

    # WAT001: required event type not covered by any enabled, delivering rule.
    for event_type, label in sorted(REQUIRED_EVENT_TYPES.items()):
        if event_type not in active_types:
            findings.append(Finding("WAT001", "HIGH", event_type,
                                    f"{label} is not covered by any enabled rule with a topic; this change would pass silently"))

    # WAT004: same event type claimed by more than one active rule (double paging).
    seen = {}
    for rule in rules:
        if rule.get("enabled") is False:
            continue
        for event_type in rule["event_types"]:
            if event_type in seen:
                findings.append(Finding("WAT004", "LOW", event_type,
                                        f"covered by both '{seen[event_type]}' and '{rule['name']}'; duplicate notifications"))
            else:
                seen[event_type] = rule["name"]

    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.subject, f.message))
