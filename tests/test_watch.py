import unittest

from oci_ootb_events_security_watch.watch import REQUIRED_EVENT_TYPES, check_coverage


def rule(name, event_types, enabled=True, topic="ocid1.onstopic.example.security"):
    return {
        "name": name,
        "enabled": enabled,
        "event_types": event_types,
        "actions": {"topic": topic} if topic else {},
    }


def full_covering_rules():
    return [
        rule("iam", ["com.oraclecloud.identitycontrolplane.createpolicy",
                     "com.oraclecloud.identitycontrolplane.updatepolicy",
                     "com.oraclecloud.identitycontrolplane.createapikey"]),
        rule("net", ["com.oraclecloud.virtualnetwork.updatesecuritylist"]),
        rule("bucket", ["com.oraclecloud.objectstorage.updatebucket"]),
    ]


def rule_ids(findings):
    return {f.rule_id for f in findings}


class TestCoverage(unittest.TestCase):
    def test_complete_set_has_no_findings(self):
        self.assertEqual(check_coverage({"rules": full_covering_rules()}), [])

    def test_wat001_all_uncovered_when_empty(self):
        findings = check_coverage({"rules": []})
        wat001 = [f for f in findings if f.rule_id == "WAT001"]
        self.assertEqual(len(wat001), len(REQUIRED_EVENT_TYPES))
        self.assertTrue(all(f.severity == "HIGH" for f in wat001))

    def test_wat001_single_gap(self):
        rules = full_covering_rules()
        rules = [r for r in rules if r["name"] != "bucket"]
        findings = check_coverage({"rules": rules})
        self.assertIn("WAT001", rule_ids(findings))
        self.assertTrue(any("updatebucket" in f.subject for f in findings))

    def test_wat001_disabled_rule_does_not_cover(self):
        rules = full_covering_rules()
        rules[1]["enabled"] = False
        ids = rule_ids(check_coverage({"rules": rules}))
        self.assertIn("WAT001", ids)
        self.assertIn("WAT002", ids)

    def test_wat001_rule_without_topic_does_not_cover(self):
        rules = full_covering_rules()
        rules[2]["actions"] = {}
        ids = rule_ids(check_coverage({"rules": rules}))
        self.assertIn("WAT001", ids)
        self.assertIn("WAT003", ids)

    def test_wat002_disabled_rule(self):
        findings = check_coverage({"rules": [rule("r", ["x"], enabled=False)]})
        self.assertIn("WAT002", rule_ids(findings))

    def test_wat003_no_topic(self):
        findings = check_coverage({"rules": [rule("r", ["x"], topic=None)]})
        self.assertIn("WAT003", rule_ids(findings))

    def test_wat004_duplicate_coverage(self):
        rules = full_covering_rules()
        rules.append(rule("dup", ["com.oraclecloud.virtualnetwork.updatesecuritylist"]))
        self.assertIn("WAT004", rule_ids(check_coverage({"rules": rules})))

    def test_wat004_not_for_disabled_duplicate(self):
        rules = full_covering_rules()
        rules.append(rule("dup", ["com.oraclecloud.virtualnetwork.updatesecuritylist"], enabled=False))
        self.assertNotIn("WAT004", rule_ids(check_coverage({"rules": rules})))

    def test_findings_sorted_high_first(self):
        findings = check_coverage({"rules": [rule("r", ["x"], enabled=False, topic=None)]})
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[-1].severity, "MEDIUM")

    def test_missing_rules_list_rejected(self):
        with self.assertRaises(ValueError):
            check_coverage({"items": []})

    def test_rule_missing_name_rejected(self):
        with self.assertRaises(ValueError):
            check_coverage({"rules": [{"event_types": []}]})

    def test_rule_missing_event_types_rejected(self):
        with self.assertRaises(ValueError):
            check_coverage({"rules": [{"name": "r"}]})


if __name__ == "__main__":
    unittest.main()
