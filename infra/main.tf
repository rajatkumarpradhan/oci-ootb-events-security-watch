# OCI Events security-notification wiring (template; NOT applied).
#
# OCI Events is the built-in OCI feature that reacts to resource changes; the
# standard security posture is event rules that notify a topic when IAM
# policy, network security, bucket settings, or credentials change. This
# template creates the notification topic and one rule per watch area. The
# local checker in src/ verifies a rule set actually covers every required
# event type.
#
# This file has NOT been plan/apply validated against a tenancy - it is a
# structural template. Review against the current provider docs before any
# real apply.

terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

variable "compartment_ocid" {
  type        = string
  description = "OCID of the compartment that owns the topic and rules"
}

resource "oci_ons_notification_topic" "security_watch" {
  compartment_id = var.compartment_ocid
  name           = "security-watch"
}

resource "oci_events_rule" "iam_watch" {
  compartment_id = var.compartment_ocid
  display_name   = "iam-watch"
  is_enabled     = true
  condition      = "{\"eventType\": [\"com.oraclecloud.identitycontrolplane.createpolicy\", \"com.oraclecloud.identitycontrolplane.updatepolicy\", \"com.oraclecloud.identitycontrolplane.createapikey\"]}"

  actions {
    action_type = "ONS"
    topic_id    = oci_ons_notification_topic.security_watch.id
  }
}

resource "oci_events_rule" "network_watch" {
  compartment_id = var.compartment_ocid
  display_name   = "network-watch"
  is_enabled     = true
  condition      = "{\"eventType\": [\"com.oraclecloud.virtualnetwork.updatesecuritylist\"]}"

  actions {
    action_type = "ONS"
    topic_id    = oci_ons_notification_topic.security_watch.id
  }
}

resource "oci_events_rule" "bucket_watch" {
  compartment_id = var.compartment_ocid
  display_name   = "bucket-watch"
  is_enabled     = true
  condition      = "{\"eventType\": [\"com.oraclecloud.objectstorage.updatebucket\"]}"

  actions {
    action_type = "ONS"
    topic_id    = oci_ons_notification_topic.security_watch.id
  }
}
