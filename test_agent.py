import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agent import (
    deliver,
    env_choice,
    handle_commands,
    positive_int,
    stable_cluster_identifier,
    stable_cluster_identity_source,
    validate_platform_url,
)
from collector import ClusterCollector, AGENT_VERSION, classify_platform
from privacy import alias_identifier, sanitize_value, scrub_log_text, scrub_text


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


class CommandHandlingTests(unittest.TestCase):
    @patch("agent.submit_command_result")
    @patch("agent.fetch_commands")
    def test_null_since_seconds_uses_collector_default(
        self, fetch_commands_mock, submit_command_result_mock
    ):
        fetch_commands_mock.return_value = [
            {
                "id": 17,
                "type": "pod_logs",
                "payload": {
                    "namespace": "data",
                    "pod": "backup-attempt",
                    "container": "logical-backup",
                    "tail_lines": 200,
                    "since_seconds": None,
                },
            }
        ]
        collector = Mock()
        collector.fetch_pod_logs.return_value = (
            {"lines": ["backup failed"], "line_count": 1},
            0,
        )

        handle_commands(
            Mock(),
            "https://api.krevopilot.com",
            "agent-key",
            collector,
            True,
        )

        collector.fetch_pod_logs.assert_called_once_with(
            "data",
            "backup-attempt",
            "logical-backup",
            previous=False,
            tail_lines=200,
            since_seconds=None,
        )
        self.assertEqual(
            submit_command_result_mock.call_args.args[4]["status"], "completed"
        )

    @patch("agent.submit_command_result")
    @patch("agent.fetch_commands")
    def test_deployment_inventory_command_is_allowlisted_and_returned(
        self, fetch_commands_mock, submit_command_result_mock
    ):
        fetch_commands_mock.return_value = [
            {
                "id": 18,
                "type": "deployment_inventory",
                "payload": {"categories": ["storage", "argocd"]},
            }
        ]
        collector = Mock()
        collector.fetch_deployment_inventory.return_value = (
            {
                "coverage": {"storage": True, "argocd": True},
                "storage_classes": ["standard"],
                "argo_cd": {"installed": True, "namespace": "argocd"},
            },
            0,
        )

        handle_commands(
            Mock(),
            "https://api.krevopilot.com",
            "agent-key",
            collector,
            True,
        )

        collector.fetch_deployment_inventory.assert_called_once_with(["storage", "argocd"])
        submitted = submit_command_result_mock.call_args.args[4]
        self.assertEqual(submitted["status"], "completed")
        self.assertEqual(submitted["result"]["storage_classes"], ["standard"])


class PrivacyTests(unittest.TestCase):
    def test_physical_cluster_id_survives_key_salt_and_alias_changes(self):
        source = "kube-system-uid:31b99b22-377b-4ac3-a42d-758209291938"
        first = stable_cluster_identifier(source, "kube-system-namespace-uid-v1")
        second = stable_cluster_identifier(source, "kube-system-namespace-uid-v1")
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("cluster-"))

    def test_cluster_identity_uses_kube_system_uid_instead_of_friendly_alias(self):
        collector = Mock()
        collector.core.read_namespace.return_value = ns(
            metadata=ns(uid="31b99b22-377b-4ac3-a42d-758209291938")
        )
        first = stable_cluster_identity_source(collector, "old-friendly-name")
        second = stable_cluster_identity_source(collector, "new-friendly-name")
        self.assertEqual(first, second)
        self.assertEqual(first[1], "kube-system-namespace-uid-v1")

    def test_aliases_are_stable_and_do_not_reveal_names(self):
        first = alias_identifier(b"0123456789abcdef", "pod", "payments-api-123")
        second = alias_identifier(b"0123456789abcdef", "pod", "payments-api-123")
        self.assertEqual(first, second)
        self.assertNotIn("payments", first)

    def test_scrubs_common_sensitive_values(self):
        cleaned, count = scrub_text(
            "password=hunter2 owner=dev@example.com source=10.0.0.8 Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
        )
        self.assertGreaterEqual(count, 4)
        self.assertNotIn("hunter2", cleaned)
        self.assertNotIn("dev@example.com", cleaned)
        self.assertNotIn("10.0.0.8", cleaned)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", cleaned)

    def test_scrubs_identifiers_from_event_messages(self):
        cleaned, count = scrub_text("Pod customer-api-abc failed", ["customer-api-abc"])
        self.assertEqual(count, 1)
        self.assertNotIn("customer-api-abc", cleaned)

    def test_quoted_event_details_are_removed(self):
        cleaned, count = scrub_text('Failed to pull image "private.registry/customer/api:v7"')
        self.assertGreaterEqual(count, 1)
        self.assertNotIn("private.registry", cleaned)
    def test_sensitive_dictionary_keys_are_removed(self):
        cleaned, count = sanitize_value({"safe": "ok", "api_token": "secret-value"})
        self.assertEqual(cleaned["safe"], "ok")
        self.assertEqual(cleaned["api_token"], "[REDACTED_SENSITIVE_FIELD]")
        self.assertEqual(count, 1)

    def test_log_scrubbing_keeps_internal_ips_when_allowed(self):
        cleaned, count = scrub_log_text(
            "user=dev@example.com db_password=hunter2 internal=10.0.0.8 public=8.8.8.8 Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
            mask_emails=True,
            mask_public_ips=True,
            mask_internal_ips=False,
        )
        self.assertGreaterEqual(count, 4)
        self.assertIn("10.0.0.8", cleaned)
        self.assertNotIn("8.8.8.8", cleaned)
        self.assertNotIn("hunter2", cleaned)
        self.assertNotIn("dev@example.com", cleaned)


class ConfigurationTests(unittest.TestCase):
    def test_https_is_required_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                validate_platform_url("http://platform.example.com")

    def test_http_can_be_enabled_for_minikube(self):
        with patch.dict(os.environ, {"ALLOW_INSECURE_HTTP": "true"}, clear=True):
            self.assertEqual(validate_platform_url("http://host.minikube.internal:8000/"), "http://host.minikube.internal:8000")

    def test_integer_configuration_is_bounded(self):
        with patch.dict(os.environ, {"MAX_PODS": "501"}, clear=True):
            with self.assertRaises(RuntimeError):
                positive_int("MAX_PODS", 150, 500)

    def test_choice_configuration_is_bounded(self):
        with patch.dict(os.environ, {"EVENT_MESSAGE_MODE": "raw"}, clear=True):
            with self.assertRaises(RuntimeError):
                env_choice("EVENT_MESSAGE_MODE", "scrubbed", {"scrubbed", "summary", "none"})


class DeliveryTests(unittest.TestCase):
    def test_delivery_uses_agent_header_and_timeouts(self):
        response = Mock()
        response.json.return_value = {"accepted": True, "snapshot_id": 7}
        session = Mock()
        session.post.return_value = response
        result = deliver(session, "https://platform.example/api/agent/ingest", "agent-secret", {"ok": True}, True)
        self.assertEqual(result["snapshot_id"], 7)
        kwargs = session.post.call_args.kwargs
        self.assertEqual(kwargs["headers"]["X-Agent-Key"], "agent-secret")
        self.assertEqual(kwargs["timeout"], (5, 20))
        response.raise_for_status.assert_called_once()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.collector = ClusterCollector(b"0123456789abcdef", max_pods=10, max_events=10, manifests_enabled=False)
        waiting = ns(reason="CrashLoopBackOff", exit_code=None, finished_at=None)
        state = ns(waiting=waiting, terminated=None, running=None)
        last_terminated = ns(reason="OOMKilled", message=None, exit_code=137, signal=None, finished_at=datetime(2026, 7, 20, tzinfo=timezone.utc))
        last_state = ns(waiting=None, terminated=last_terminated, running=None)
        container_status = ns(
            name="api", ready=False, restart_count=4, started=True,
            image="ghcr.io/company/api:v2", image_id="ghcr.io/company/api@sha256:abc123",
            state=state, last_state=last_state,
        )
        resources = ns(requests={"cpu": "100m", "memory": "128Mi"}, limits={"cpu": "500m", "memory": "256Mi"})
        liveness_probe = ns(http_get=ns(path="/healthz", port=8080), exec=None, tcp_socket=None, initial_delay_seconds=10, period_seconds=5, failure_threshold=3)
        security_context = ns(run_as_non_root=True, read_only_root_filesystem=False, privileged=False)
        container = ns(
            name="api", resources=resources, command=["/app/start.sh"], args=["--flag"],
            liveness_probe=liveness_probe, readiness_probe=None, startup_probe=None,
            security_context=security_context,
        )
        condition = ns(type="Ready", status="False", reason="ContainersNotReady")
        owner = ns(name="customer-api-7d9", kind="ReplicaSet", controller=True)
        now = datetime.now(timezone.utc)
        self.pod = ns(
            metadata=ns(
                name="customer-api-7d9-x1", namespace="production", generate_name=None,
                owner_references=[owner], uid="pod-uid-123", creation_timestamp=now,
                deletion_timestamp=None,
                labels={"tier": "backend", "team": "payments"},
                annotations={"deployment.kubernetes.io/revision": "7", "internal.note": "not-a-revision"},
            ),
            spec=ns(
                node_name="node-private-1", containers=[container],
                init_containers=[], ephemeral_containers=[],
                priority_class_name="high-priority", restart_policy="Always",
            ),
            status=ns(
                phase="Running", start_time=now, container_statuses=[container_status], conditions=[condition],
                init_container_statuses=[], ephemeral_container_statuses=[],
                reason=None, message=None, pod_ip="10.1.2.3", host_ip="10.0.0.1", qos_class="Burstable",
            ),
        )
        involved = ns(name="customer-api-7d9-x1", namespace="production", kind="Pod")
        self.event = ns(
            type="Warning",
            reason="BackOff",
            message="Back-off restarting customer-api-7d9-x1 at 10.0.0.9",
            involved_object=involved,
            count=4,
            last_timestamp=now,
            event_time=None,
            metadata=ns(name="customer-api-event", namespace="production", creation_timestamp=now),
        )
        node_info = ns(kubelet_version="v1.30.0", operating_system="linux", architecture="amd64")
        node_conditions = [ns(type="Ready", status="True"), ns(type="MemoryPressure", status="False"), ns(type="DiskPressure", status="False"), ns(type="PIDPressure", status="False")]
        self.node = ns(metadata=ns(name="node-private-1"), status=ns(conditions=node_conditions, capacity={"cpu": "4", "memory": "8Gi"}, allocatable={"cpu": "3900m", "memory": "7Gi"}, node_info=node_info))
        self.collector.core = Mock()
        self.collector.core.list_pod_for_all_namespaces.return_value = ns(items=[self.pod])
        self.collector.core.list_event_for_all_namespaces.return_value = ns(items=[self.event])
        self.collector.core.list_node.return_value = ns(items=[self.node])
        self.collector.metrics = Mock()
        self.collector.metrics.list_cluster_custom_object.side_effect = RuntimeError("metrics unavailable")
        self.collector.apps = Mock()
        self.collector.apps.list_replica_set_for_all_namespaces.return_value = ns(items=[])

    def test_collector_returns_privacy_filtered_health_snapshot(self):
        signals, redactions = self.collector.collect()
        self.assertEqual(signals["summary"]["pods_observed"], 1)
        self.assertEqual(signals["pods"][0]["containers"][0]["reason"], "CrashLoopBackOff")
        self.assertEqual(signals["pods"][0]["namespace"], "production")
        self.assertEqual(signals["warning_events"][0]["namespace"], "production")
        self.assertNotIn("customer-api", str(signals))
        self.assertNotIn("10.0.0.9", str(signals))
        self.assertFalse(signals["metrics"]["available"])
        self.assertGreater(redactions, 0)
        # The snapshot always carries a platform block, even when nothing is recognised.
        self.assertIn("platform", signals)
        self.assertIn("distribution", signals["platform"])
        self.assertIn("confidence", signals["platform"])

    def test_collector_never_reads_logs_or_secrets(self):
        self.collector.collect()
        called_names = {call[0] for call in self.collector.core.method_calls}
        self.assertNotIn("read_namespaced_pod_log", called_names)
        self.assertNotIn("read_namespaced_secret", called_names)

    def test_deployment_inventory_returns_only_requested_safe_facts(self):
        self.collector.storage_api = Mock()
        self.collector.storage_api.list_storage_class.return_value = ns(items=[
            ns(metadata=ns(name="standard", annotations={"storageclass.kubernetes.io/is-default-class": "true"}))
        ])

        result, _redactions = self.collector.fetch_deployment_inventory(
            ["storage", "logs", "secrets", "manifests"]
        )

        self.assertEqual(result["coverage"], {"storage": True})
        self.assertEqual(result["default_storage_class"], "standard")
        self.assertNotIn("logs", result)
        self.assertNotIn("secrets", result)
        self.assertNotIn("manifests", result)
        called_names = {call[0] for call in self.collector.core.method_calls}
        self.assertNotIn("read_namespaced_pod_log", called_names)
        self.assertNotIn("read_namespaced_secret", called_names)

    def test_on_demand_logs_are_disabled_by_default(self):
        with self.assertRaises(RuntimeError):
            self.collector.fetch_pod_logs("production", "customer-api-7d9-x1")

    def test_on_demand_logs_are_redacted_when_enabled(self):
        self.collector.logs_enabled = True
        self.collector.collect()
        self.collector.core.read_namespaced_pod_log.return_value = (
            "connecting to postgres://app:hunter2@10.0.0.8:5432/db "
            "public=8.8.8.8 token=super-secret-token"
        )
        pod_alias = self.collector.alias("pod", "customer-api-7d9-x1")
        container_alias = self.collector.alias("container", "api")
        result, redactions = self.collector.fetch_pod_logs("production", pod_alias, container_alias, tail_lines=1000, since_seconds=999999)
        self.assertGreater(redactions, 0)
        self.assertEqual(result["tail_lines"], self.collector.log_max_lines)
        self.assertEqual(result["since_seconds"], self.collector.log_max_lookback_minutes * 60)
        self.assertNotIn("hunter2", result["logs"])
        self.assertNotIn("super-secret-token", result["logs"])
        self.assertNotIn("8.8.8.8", result["logs"])
        self.assertIn("10.0.0.8", result["logs"])

    def test_on_demand_logs_without_lookback_reads_retained_job_logs(self):
        self.collector.logs_enabled = True
        self.collector.collect()
        self.collector.core.read_namespaced_pod_log.return_value = "old retained job failure"
        pod_alias = self.collector.alias("pod", "customer-api-7d9-x1")
        container_alias = self.collector.alias("container", "api")

        result, _ = self.collector.fetch_pod_logs(
            "production",
            pod_alias,
            container_alias,
            tail_lines=250,
            since_seconds=None,
        )

        self.assertIsNone(result["since_seconds"])
        self.collector.core.read_namespaced_pod_log.assert_called_once_with(
            name="customer-api-7d9-x1",
            namespace="production",
            container="api",
            previous=False,
            tail_lines=250,
            since_seconds=None,
            timestamps=True,
        )
        self.assertIn("old retained job failure", result["logs"])

    def test_on_demand_logs_require_the_exact_namespace_pod_pair(self):
        self.collector.logs_enabled = True
        self.collector.collect()
        pod_alias = self.collector.alias("pod", "customer-api-7d9-x1")
        container_alias = self.collector.alias("container", "api")

        with self.assertRaisesRegex(RuntimeError, "namespace/pod target is not"):
            self.collector.fetch_pod_logs("different-namespace", pod_alias, container_alias)

        self.collector.core.read_namespaced_pod_log.assert_not_called()

    def test_on_demand_logs_reject_unknown_container(self):
        self.collector.logs_enabled = True
        self.collector.collect()
        pod_alias = self.collector.alias("pod", "customer-api-7d9-x1")

        with self.assertRaisesRegex(RuntimeError, "container is not present"):
            self.collector.fetch_pod_logs("production", pod_alias, "container-does-not-exist")

        self.collector.core.read_namespaced_pod_log.assert_not_called()

    def test_on_demand_logs_do_not_cross_namespaces_for_duplicate_pod_names(self):
        self.collector.logs_enabled = True
        pod_alias = self.collector.alias("pod", "same-pod")
        container_alias = self.collector.alias("container", "api")
        self.collector.pod_lookup = {
            f"team-a/{pod_alias}": {
                "namespace": "team-a",
                "namespace_alias": "team-a",
                "pod": "same-pod",
                "pod_alias": pod_alias,
                "containers": {container_alias: "api"},
            },
            f"team-b/{pod_alias}": {
                "namespace": "team-b",
                "namespace_alias": "team-b",
                "pod": "same-pod",
                "pod_alias": pod_alias,
                "containers": {container_alias: "api"},
            },
        }
        self.collector.core.read_namespaced_pod_log.return_value = "selected namespace"

        self.collector.fetch_pod_logs("team-b", pod_alias, container_alias)

        self.collector.core.read_namespaced_pod_log.assert_called_once_with(
            name="same-pod",
            namespace="team-b",
            container="api",
            previous=False,
            tail_lines=200,
            since_seconds=None,
            timestamps=True,
        )

    @patch("collector.requests.get")
    def test_on_demand_logs_can_query_loki_instead_of_kubernetes_logs(self, mock_get):
        self.collector.logs_enabled = True
        self.collector.external_log_source = "loki"
        self.collector.external_log_source_url = "http://loki-gateway.observability.svc.cluster.local"
        self.collector.collect()
        response = Mock()
        response.json.return_value = {
            "status": "success",
            "data": {
                "result": [
                    {
                        "stream": {"namespace": "production", "pod": "customer-api-7d9-x1", "container": "api"},
                        "values": [
                            ["1000000000", "INFO connected to 10.0.0.8"],
                            ["2000000000", "ERROR token=super-secret-token public=8.8.8.8"],
                        ],
                    }
                ]
            },
        }
        mock_get.return_value = response
        pod_alias = self.collector.alias("pod", "customer-api-7d9-x1")
        container_alias = self.collector.alias("container", "api")
        result, redactions = self.collector.fetch_pod_logs("production", pod_alias, container_alias, tail_lines=50, since_seconds=600)

        self.assertEqual(result["source"], "loki")
        self.assertGreater(redactions, 0)
        self.collector.core.read_namespaced_pod_log.assert_not_called()
        self.assertNotIn("super-secret-token", result["logs"])
        self.assertNotIn("8.8.8.8", result["logs"])
        self.assertIn("10.0.0.8", result["logs"])
        kwargs = mock_get.call_args.kwargs
        self.assertEqual(kwargs["params"]["query"], '{namespace="production",pod="customer-api-7d9-x1",container="api"}')
        self.assertTrue(mock_get.call_args.args[0].endswith("/loki/api/v1/query_range"))

    def test_snapshot_reports_loki_policy_without_collecting_logs(self):
        self.collector.logs_enabled = True
        self.collector.external_log_source = "loki"
        self.collector.external_log_source_url = "http://loki-gateway.observability.svc.cluster.local"
        signals, _redactions = self.collector.collect()
        policy = signals["collection_policy"]
        self.assertEqual(policy["external_log_source"], "loki")
        self.assertTrue(policy["external_log_source_configured"])
        self.assertFalse(policy["logs_collected"])

    def test_collector_can_alias_namespaces(self):
        self.collector.preserve_namespaces = False
        signals, _redactions = self.collector.collect()
        self.assertNotEqual(signals["pods"][0]["namespace"], "production")
        self.assertTrue(signals["pods"][0]["namespace"].startswith("namespace-"))
        self.assertNotIn("production", str(signals))

    def test_event_message_summary_mode_removes_free_text(self):
        self.collector.event_message_mode = "summary"
        signals, _redactions = self.collector.collect()
        self.assertEqual(signals["warning_events"][0]["message"], "Pod warning reason: BackOff")
        self.assertNotIn("10.0.0.9", str(signals))

    def test_container_reports_previous_terminated_state_with_last_prefix(self):
        signals, _redactions = self.collector.collect()
        container = signals["pods"][0]["containers"][0]
        self.assertEqual(container["reason"], "CrashLoopBackOff")
        self.assertEqual(container["last_state"], "terminated")
        self.assertEqual(container["last_reason"], "OOMKilled")
        self.assertEqual(container["last_exit_code"], 137)
        self.assertIsNotNone(container["last_finished_at"])

    def test_container_without_previous_state_has_no_last_prefixed_keys(self):
        waiting = ns(reason="CrashLoopBackOff", exit_code=None, finished_at=None)
        state = ns(waiting=waiting, terminated=None, running=None)
        container_status = ns(name="api", ready=False, restart_count=0, state=state)
        container = ns(name="api", resources=ns(requests={}, limits={}))
        pod = ns(
            metadata=ns(name="fresh-pod", namespace="production", generate_name=None, owner_references=[]),
            spec=ns(node_name="node-1", containers=[container]),
            status=ns(phase="Running", start_time=None, container_statuses=[container_status], conditions=[]),
        )
        self.collector.core.list_pod_for_all_namespaces.return_value = ns(items=[pod])

        signals, _redactions = self.collector.collect()

        container_out = signals["pods"][0]["containers"][0]
        self.assertNotIn("last_state", container_out)
        self.assertNotIn("last_reason", container_out)
        self.assertNotIn("last_exit_code", container_out)
        self.assertNotIn("last_finished_at", container_out)

    def test_init_container_status_is_collected_separately(self):
        init_waiting = None
        init_terminated = ns(reason="Completed", message=None, exit_code=0, signal=None, finished_at=None)
        init_state = ns(waiting=init_waiting, terminated=init_terminated, running=None)
        init_status = ns(name="migrate", ready=True, restart_count=0, state=init_state)
        init_spec_container = ns(name="migrate", resources=ns(requests={}, limits={}))
        self.pod.spec.init_containers = [init_spec_container]
        self.pod.status.init_container_statuses = [init_status]

        signals, _redactions = self.collector.collect()

        init_containers = signals["pods"][0]["init_containers"]
        self.assertEqual(len(init_containers), 1)
        self.assertEqual(init_containers[0]["state"], "terminated")
        self.assertEqual(init_containers[0]["reason"], "Completed")

    def test_container_includes_command_args_probes_and_security_context(self):
        signals, _redactions = self.collector.collect()
        container = signals["pods"][0]["containers"][0]
        self.assertEqual(container["command"], ["/app/start.sh"])
        self.assertEqual(container["args"], ["--flag"])
        self.assertEqual(container["probes"]["liveness"]["type"], "httpGet")
        self.assertEqual(container["probes"]["liveness"]["failure_threshold"], 3)
        self.assertTrue(container["security_context"]["run_as_non_root"])
        self.assertFalse(container["security_context"]["privileged"])

    def test_pod_level_identity_and_state_fields_are_collected(self):
        signals, _redactions = self.collector.collect()
        pod = signals["pods"][0]
        self.assertEqual(pod["uid"], "pod-uid-123")
        self.assertIsNotNone(pod["creation_timestamp"])
        self.assertEqual(pod["qos_class"], "Burstable")
        self.assertIn("pod_ip", pod)
        self.assertIn("host_ip", pod)
        self.assertEqual(pod["restart_policy"], "Always")
        self.assertEqual(pod["priority_class_name"], "high-priority")
        self.assertEqual(pod["labels"], {"tier": "backend", "team": "payments"})
        self.assertIn("deployment.kubernetes.io/revision", pod["annotation_keys"])
        self.assertIn("internal.note", pod["annotation_keys"])
        self.assertEqual(pod["revision_annotations"], {"deployment.kubernetes.io/revision": "7"})

    def test_replicaset_owner_resolves_to_deployment(self):
        rs_owner = ns(name="customer-api", kind="Deployment", controller=True)
        replica_set = ns(metadata=ns(namespace="production", name="customer-api-7d9", owner_references=[rs_owner]))
        self.collector.apps.list_replica_set_for_all_namespaces.return_value = ns(items=[replica_set])

        signals, _redactions = self.collector.collect()

        pod = signals["pods"][0]
        self.assertEqual(pod["workload_kind"], "Deployment")
        self.assertEqual(pod["immediate_owner_kind"], "ReplicaSet")
        self.assertIn("immediate_owner_name", pod)

    def test_orphaned_replicaset_keeps_replicaset_kind(self):
        replica_set = ns(metadata=ns(namespace="production", name="customer-api-7d9", owner_references=[]))
        self.collector.apps.list_replica_set_for_all_namespaces.return_value = ns(items=[replica_set])

        signals, _redactions = self.collector.collect()

        pod = signals["pods"][0]
        self.assertEqual(pod["workload_kind"], "ReplicaSet")
        self.assertNotIn("immediate_owner_kind", pod)

    def test_replicaset_lookup_failure_degrades_gracefully(self):
        self.collector.apps.list_replica_set_for_all_namespaces.side_effect = RuntimeError("Forbidden")

        signals, _redactions = self.collector.collect()

        pod = signals["pods"][0]
        self.assertEqual(pod["workload_kind"], "ReplicaSet")
        self.assertNotIn("immediate_owner_kind", pod)

    def test_event_object_name_matches_pod_alias(self):
        signals, _redactions = self.collector.collect()
        self.assertEqual(signals["warning_events"][0]["object_name"], signals["pods"][0]["pod"])

    def test_event_object_name_matches_workload_alias_for_deployment_kind_event(self):
        rs_owner = ns(name="customer-api", kind="Deployment", controller=True)
        replica_set = ns(metadata=ns(namespace="production", name="customer-api-7d9", owner_references=[rs_owner]))
        self.collector.apps.list_replica_set_for_all_namespaces.return_value = ns(items=[replica_set])
        involved = ns(name="customer-api", namespace="production", kind="Deployment")
        self.event.involved_object = involved

        signals, _redactions = self.collector.collect()

        self.assertEqual(signals["warning_events"][0]["object_name"], signals["pods"][0]["workload"])

    def test_event_object_name_matches_node_alias(self):
        involved = ns(name="node-private-1", namespace="", kind="Node")
        self.event.involved_object = involved

        signals, _redactions = self.collector.collect()

        self.assertEqual(signals["warning_events"][0]["object_name"], signals["nodes"][0]["node"])

    def test_event_object_name_none_for_unsupported_kind(self):
        involved = ns(name="some-webhook", namespace="production", kind="ValidatingWebhookConfiguration")
        self.event.involved_object = involved

        signals, _redactions = self.collector.collect()

        self.assertIsNone(signals["warning_events"][0]["object_name"])

    def test_event_first_seen_is_collected(self):
        self.event.first_timestamp = datetime(2026, 7, 20, tzinfo=timezone.utc)
        signals, _redactions = self.collector.collect()
        self.assertEqual(signals["warning_events"][0]["first_seen"], "2026-07-20T00:00:00+00:00")

    def test_node_without_spec_has_empty_taints(self):
        """The existing fixture's node has no .spec at all - confirms this doesn't crash
        collection and defaults to an empty list rather than a missing key."""
        signals, _redactions = self.collector.collect()
        self.assertEqual(signals["nodes"][0]["taints"], [])

    def test_node_taints_are_collected(self):
        taint = ns(key="dedicated", value="gpu", effect="NoSchedule")
        self.node.spec = ns(taints=[taint])
        signals, _redactions = self.collector.collect()
        self.assertEqual(signals["nodes"][0]["taints"], [{"key": "dedicated", "value": "gpu", "effect": "NoSchedule"}])


class ManifestCollectionTests(unittest.TestCase):
    def setUp(self):
        self.collector = ClusterCollector(b"0123456789abcdef", max_pods=10, max_events=10, manifests_enabled=True)

    def test_secret_manifest_never_contains_secret_values_or_key_names(self):
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "db-secret", "namespace": "production"},
            "type": "Opaque",
            "data": {"DATABASE_PASSWORD": "c2VjcmV0"},
            "stringData": {"STRIPE_TOKEN": "live-secret-token"},
        }
        self.collector.api_client = Mock()
        self.collector.api_client.sanitize_for_serialization.return_value = secret

        item, _redactions = self.collector._manifest_item("Secret", object())

        self.assertEqual(item["kind"], "Secret")
        self.assertIn("dataKeyCount: 1", item["yaml"])
        self.assertIn("stringDataKeyCount: 1", item["yaml"])
        self.assertNotIn("c2VjcmV0", item["yaml"])
        self.assertNotIn("live-secret-token", item["yaml"])
        self.assertNotIn("DATABASE_PASSWORD", item["yaml"])
        self.assertNotIn("STRIPE_TOKEN", item["yaml"])

    def test_workload_manifest_redacts_env_values_but_keeps_refs(self):
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "checkout-api", "namespace": "ecommerce"},
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "image": "ghcr.io/company/checkout:v1",
                                "env": [
                                    {"name": "DATABASE_URL", "value": "postgres://app:secret@db:5432/app"},
                                    {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "checkout-secret", "key": "password"}}},
                                ],
                            }
                        ]
                    }
                },
            },
        }
        self.collector.api_client = Mock()
        self.collector.api_client.sanitize_for_serialization.return_value = deployment

        item, _redactions = self.collector._manifest_item("Deployment", object())

        self.assertIn("replicas: 2", item["yaml"])
        self.assertIn("secretKeyRef", item["yaml"])
        self.assertIn("checkout-secret", item["yaml"])
        self.assertNotIn("postgres://app:secret", item["yaml"])
        self.assertIn("REDACTED_ENV_VALUE", item["yaml"])

    def _manifest(self, collector, kind, raw):
        collector.api_client = Mock()
        collector.api_client.sanitize_for_serialization.return_value = raw
        item, _redactions = collector._manifest_item(kind, object())
        return item

    def _replicaset(self):
        return {
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "payment-gateway-76dccd59c6",
                "namespace": "krevo-demo",
                "ownerReferences": [{"kind": "Deployment", "name": "payment-gateway"}],
            },
            "spec": {"replicas": 1},
        }

    def _deployment(self):
        return {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "payment-gateway", "namespace": "krevo-demo"},
            "spec": {"replicas": 1},
        }

    def test_manifest_carries_the_same_workload_alias_the_pod_reports(self):
        """Without this the platform cannot tell which manifest belongs to a failing pod."""
        item = self._manifest(self.collector, "ReplicaSet", self._replicaset())
        pod_workload = self.collector.alias("workload", "krevo-demo/ReplicaSet/payment-gateway-76dccd59c6")
        self.assertEqual(item["workload_ref"], pod_workload)

    def test_manifest_records_owner_so_the_platform_can_reach_the_deployment(self):
        replicaset = self._manifest(self.collector, "ReplicaSet", self._replicaset())
        deployment = self._manifest(self.collector, "Deployment", self._deployment())
        self.assertEqual(replicaset["owner"]["kind"], "Deployment")
        self.assertEqual(replicaset["owner"]["name"], "payment-gateway")
        self.assertEqual(replicaset["owner"]["workload_ref"], deployment["workload_ref"])

    def test_object_names_are_real_so_engineers_can_act_on_them(self):
        deployment = self._manifest(self.collector, "Deployment", self._deployment())
        self.assertEqual(deployment["object"], "payment-gateway")
        self.assertIn("payment-gateway", deployment["yaml"])

    def test_object_names_can_be_aliased_without_breaking_the_pod_link(self):
        private = ClusterCollector(
            b"0123456789abcdef", max_pods=10, max_events=10,
            manifests_enabled=True, manifest_real_names=False,
        )
        deployment = self._manifest(private, "Deployment", self._deployment())
        self.assertNotEqual(deployment["object"], "payment-gateway")
        self.assertNotIn("payment-gateway", deployment["yaml"])
        replicaset = self._manifest(private, "ReplicaSet", self._replicaset())
        self.assertEqual(
            replicaset["workload_ref"],
            private.alias("workload", "krevo-demo/ReplicaSet/payment-gateway-76dccd59c6"),
        )

    def test_aliasing_object_names_redacts_container_spec_identifiers(self):
        private = ClusterCollector(
            b"0123456789abcdef", max_pods=10, max_events=10,
            manifests_enabled=True, manifest_real_names=False, preserve_namespaces=False,
        )
        deployment = self._manifest(private, "Deployment", {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "checkout-api",
                "namespace": "ecommerce",
                "labels": {"app.kubernetes.io/name": "checkout-api"},
            },
            "spec": {
                "selector": {"matchLabels": {"app.kubernetes.io/name": "checkout-api"}},
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "api",
                            "image": "ghcr.io/company/checkout-api:v1",
                            "command": ["checkout-api"],
                            "args": ["--tenant", "ecommerce"],
                        }]
                    }
                },
            },
        })
        self.assertNotIn("checkout-api", deployment["yaml"])
        self.assertNotIn("ecommerce", deployment["yaml"])
        self.assertNotIn("ghcr.io/company", deployment["yaml"])
        self.assertNotIn("--tenant", deployment["yaml"])
        self.assertIn("REDACTED", deployment["yaml"])

    def test_aliasing_object_names_does_not_depend_on_namespace_setting(self):
        """The two are separate decisions; one must not silently flip the other."""
        aliased_ns = ClusterCollector(
            b"0123456789abcdef", max_pods=10, max_events=10,
            manifests_enabled=True, preserve_namespaces=False, manifest_real_names=True,
        )
        deployment = self._manifest(aliased_ns, "Deployment", self._deployment())
        self.assertEqual(deployment["object"], "payment-gateway")
        self.assertNotEqual(deployment["namespace"], "krevo-demo")

    def test_service_cluster_ip_is_never_sent(self):
        service = self._manifest(self.collector, "Service", {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "redis-cache", "namespace": "krevo-demo"},
            "spec": {"clusterIP": "10.96.4.7", "ports": [{"port": 6379}]},
        })
        self.assertNotIn("10.96.4.7", service["yaml"])
        self.assertEqual(service["object"], "redis-cache")


class PlatformDetectionTests(unittest.TestCase):
    def test_eks_is_detected_with_high_confidence(self):
        p = classify_platform(
            provider_ids=["aws:///us-east-1a/i-0abc"],
            label_keys={"eks.amazonaws.com/nodegroup"},
            kubelet_versions=["v1.28.3-eks-4f4795d"],
            os_images=["Amazon Linux 2"],
            api_groups={"apps"},
            node_names=["ip-10-0-1-23.ec2.internal"],
        )
        self.assertEqual(p["distribution"], "eks")
        self.assertEqual(p["cloud"], "aws")
        self.assertEqual(p["display_name"], "Amazon EKS")
        self.assertEqual(p["confidence"], "high")
        self.assertEqual(p["kubernetes_version"], "1.28")

    def test_openshift_api_groups_are_definitive(self):
        p = classify_platform(
            provider_ids=["aws:///z/i"],
            label_keys=set(),
            kubelet_versions=["v1.28.6+abc"],
            os_images=["Red Hat Enterprise Linux CoreOS 415"],
            api_groups={"config.openshift.io", "route.openshift.io"},
            node_names=["master-0"],
        )
        self.assertEqual(p["distribution"], "openshift")
        self.assertEqual(p["cloud"], "aws")
        self.assertEqual(p["confidence"], "high")

    def test_okd_is_separated_from_openshift_by_node_os(self):
        p = classify_platform([], set(), ["v1.28.0"], ["Fedora CoreOS 39"], {"config.openshift.io"}, ["n"])
        self.assertEqual(p["distribution"], "okd")

    def test_kind_is_detected_from_provider_id(self):
        p = classify_platform(["kind://docker/home/home-worker"], set(), ["v1.36.1"], ["Debian"], {"apps"}, ["home-control-plane"])
        self.assertEqual(p["distribution"], "kind")
        self.assertEqual(p["cloud"], "local")

    def test_self_managed_cloud_is_medium_confidence_not_a_guessed_distro(self):
        p = classify_platform(["aws:///z/i"], {"kubernetes.io/hostname"}, ["v1.28.0"], ["Ubuntu"], {"apps"}, ["node1"])
        self.assertEqual(p["distribution"], "vanilla")
        self.assertEqual(p["cloud"], "aws")
        self.assertEqual(p["confidence"], "medium")

    def test_unrecognised_cluster_is_low_confidence_and_not_detected(self):
        p = classify_platform([], {"kubernetes.io/hostname"}, ["v1.28.0"], ["Ubuntu"], {"apps"}, ["node1"])
        self.assertEqual(p["distribution"], "unknown")
        self.assertEqual(p["confidence"], "low")
        self.assertFalse(p["detected"])

    def test_platform_ships_no_raw_provider_id_or_region(self):
        """The classification is safe to send; the raw providerID and region are not."""
        p = classify_platform(["aws:///us-east-1a/i-0secret"], {"topology.kubernetes.io/region"}, ["v1.28.3-eks-x"], [], {"apps"}, ["ip-10-0-0-1"])
        blob = str(p)
        self.assertNotIn("i-0secret", blob)
        self.assertNotIn("us-east-1a", blob)
        self.assertNotIn("ip-10-0-0-1", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
