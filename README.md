# oci-ootb-events-security-watch

**OCI Events** is the built-in OCI feature that reacts to resource changes. The standard security posture is a set of event rules that notify a topic when someone touches IAM policy, network security, bucket settings, or credentials, so nothing important passes silently. This repo ships Terraform templates for that wiring plus a local coverage checker that answers one question: does this rule set actually cover every security-relevant event type with an enabled rule that delivers somewhere?

## What it is

- `infra/` - Terraform template: one ONS notification topic plus one `oci_events_rule` per watch area (IAM, network, bucket).
- `src/` - an offline Python coverage checker with four rules (WAT001-WAT004) and CI-style exit codes.
- `samples/` - a deliberately gappy rule set (three uncovered event types, a disabled rule, a topic-less rule, one duplicate) and a complete set.
- `demo.sh` - runs the checker over both samples with expected exit codes.

## What it is NOT (honest limits)

- **The Terraform has NOT been plan/apply validated** against a tenancy. It is a structural template only; validate against the current OCI provider docs before any real apply.
- The checker works on a static JSON list of rule definitions. It does not call the OCI API to enumerate live rules, and it does not evaluate rule conditions beyond their declared event-type lists (compartment scoping, tag filters, and action types other than ONS are not modeled).
- The required event-type list is a curated starting set, not OCI's complete audit surface. Extend it for your own posture.

## Rules

| Rule | Severity | Finding |
| --- | --- | --- |
| WAT001 | HIGH | A required security event type is not covered by any enabled rule that has a notification topic |
| WAT002 | MEDIUM | Rule is disabled; its event types are unwatched |
| WAT003 | MEDIUM | Rule has no notification topic; matches would go nowhere |
| WAT004 | LOW | Same event type claimed by more than one active rule (duplicate notifications) |

Exit code 2 when any WAT001 fires; 1 on unreadable or malformed input; 0 otherwise.

## Run the local checker

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_ootb_events_security_watch samples/gappy-rules.json
PYTHONPATH=src python3 -m oci_ootb_events_security_watch samples/complete-rules.json
```

Or the end-to-end demo:

```sh
sh demo.sh
```

Expected demo output: the gappy set flags three uncovered required event types (createapikey, updatebucket, updatesecuritylist) plus the disabled rule, the topic-less rule, and one duplicate, and exits 2; the complete set reports zero findings and exits 0.

## Terraform wiring (template)

```sh
cd infra
cp terraform.tfvars.example terraform.tfvars   # fill in the compartment OCID
terraform init && terraform plan
```

This is a template - do NOT apply without reviewing against the current OCI provider docs. It was not validated against a live tenancy.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

17 unit tests cover every rule on positive and negative inputs, coverage semantics (a disabled or topic-less rule does not count as covering), finding sort order, malformed-input handling, and CLI exit codes. CI runs the same tests plus the demo on Python 3.10/3.11/3.12.
