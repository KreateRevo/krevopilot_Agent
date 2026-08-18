import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import requests
import yaml
from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

from privacy import alias_identifier, sanitize_value, scrub_log_text, scrub_text

logger = logging.getLogger("krevopilot.collector")
AGENT_VERSION = "2.0.31"
HELM_CHART_VERSION = os.getenv("HELM_CHART_VERSION", "").strip()
HELM_RELEASE_NAME = os.getenv("HELM_RELEASE_NAME", "").strip()
HELM_RELEASE_NAMESPACE = os.getenv("HELM_RELEASE_NAMESPACE", "").strip()


def load_kubernetes_config() -> str:
    try:
        config.load_incluster_config()
        return "in-cluster"
    except ConfigException:
        config.load_kube_config()
        return "kubeconfig"


_PLATFORM_DISPLAY = {
    "eks": "Amazon EKS",
    "gke": "Google GKE",
    "aks": "Azure AKS",
    "openshift": "Red Hat OpenShift",
    "okd": "OKD",
    "k3s": "K3s",
    "kind": "kind (local)",
    "minikube": "minikube (local)",
    "docker-desktop": "Docker Desktop (local)",
    "rancher": "Rancher RKE",
}


def _short_k8s_version(kubelet_versions: list[str]) -> str | None:
    """Normalise a kubelet version like 'v1.28.3-eks-4f4795d' to '1.28'."""
    for version in kubelet_versions:
        cleaned = (version or "").lstrip("vV")
        parts = cleaned.split(".")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            return f"{parts[0]}.{parts[1]}"
    return None


def classify_platform(
    provider_ids: list[str],
    label_keys: set[str],
    kubelet_versions: list[str],
    os_images: list[str],
    api_groups: set[str],
    node_names: list[str],
) -> dict[str, Any]:
    """Derive {cloud, distribution, confidence, display_name, signals} from read-only cluster
    signals. Pure and deterministic so it can be unit tested without a cluster. Ordered most
    specific first: a definitive marker (OpenShift API groups, providerID) wins over a weak one.
    """
    providers = " ".join(provider_ids).lower()
    versions = " ".join(kubelet_versions).lower()
    images = " ".join(os_images).lower()
    names = " ".join(node_names).lower()
    label_prefixes = {key.split("/", 1)[0] for key in label_keys}
    signals: list[str] = []

    def has_label(prefix: str) -> bool:
        return any(key == prefix or key.startswith(prefix) for key in label_keys) or prefix in label_prefixes

    # Cloud is derived from providerID, which is unambiguous when present.
    if providers.startswith("aws://") or "aws:///" in providers:
        cloud = "aws"
        signals.append("providerID aws://")
    elif providers.startswith("gce://") or "gce://" in providers:
        cloud = "gcp"
        signals.append("providerID gce://")
    elif "azure://" in providers:
        cloud = "azure"
        signals.append("providerID azure://")
    elif "kind://" in providers:
        cloud = "local"
        signals.append("providerID kind://")
    else:
        cloud = "unknown"

    distribution = "unknown"
    confidence = "low"

    # 1. OpenShift family is definitive: no other distribution serves these API groups.
    if {"config.openshift.io", "route.openshift.io"} & api_groups:
        signals.append("API group *.openshift.io present")
        confidence = "high"
        if "fedora coreos" in images:
            distribution = "okd"
            signals.append("Fedora CoreOS nodes")
        elif "red hat enterprise linux coreos" in images or "rhcos" in images:
            distribution = "openshift"
            signals.append("RHCOS nodes")
        else:
            distribution = "openshift"
    # 2. Managed cloud distributions.
    elif cloud == "aws" and ("-eks-" in versions or has_label("eks.amazonaws.com")):
        distribution = "eks"
        confidence = "high"
        signals.append("-eks- kubelet version" if "-eks-" in versions else "eks.amazonaws.com node label")
    elif cloud == "gcp" and ("gke" in versions or has_label("cloud.google.com")):
        distribution = "gke"
        confidence = "high"
        signals.append("gke kubelet version" if "gke" in versions else "cloud.google.com node label")
    elif cloud == "azure" and has_label("kubernetes.azure.com"):
        distribution = "aks"
        confidence = "high"
        signals.append("kubernetes.azure.com node label")
    # 3. Local / lightweight distributions.
    elif "kind://" in providers:
        distribution = "kind"
        cloud = "local"
        confidence = "high"
        signals.append("kind cluster markers")
    elif has_label("minikube.k8s.io") or "minikube" in names.split():
        distribution = "minikube"
        cloud = "local"
        confidence = "high"
        signals.append("minikube markers")
    elif "+k3s" in versions or "k3s" in versions:
        distribution = "k3s"
        confidence = "high"
        signals.append("+k3s kubelet version")
    elif "docker-desktop" in names:
        distribution = "docker-desktop"
        cloud = "local"
        confidence = "high"
        signals.append("docker-desktop node")
    elif cloud in {"aws", "gcp", "azure"}:
        # A known cloud with no managed-distribution marker: almost certainly self-managed
        # Kubernetes on VMs. Real, but we cannot claim a managed distro we did not fingerprint.
        distribution = "vanilla"
        confidence = "medium"
        signals.append(f"cloud {cloud} without a managed-distribution marker")

    if distribution in _PLATFORM_DISPLAY:
        display_name = _PLATFORM_DISPLAY[distribution]
    elif distribution == "vanilla":
        cloud_label = {"aws": "AWS", "gcp": "GCP", "azure": "Azure"}.get(cloud, "self-managed")
        display_name = f"Kubernetes on {cloud_label} (self-managed)"
    elif cloud == "local":
        display_name = "Kubernetes (local)"
    else:
        display_name = "Kubernetes (unrecognised)"

    return {
        "cloud": cloud,
        "distribution": distribution,
        "display_name": display_name,
        "kubernetes_version": _short_k8s_version(kubelet_versions),
        "confidence": confidence,
        "detection_signals": signals,
        "detected": distribution != "unknown",
    }


class ClusterCollector:
    def __init__(
        self,
        hash_salt: bytes,
        max_pods: int = 150,
        max_events: int = 60,
        preserve_namespaces: bool = True,
        event_message_mode: str = "scrubbed",
        logs_enabled: bool = False,
        log_max_lines: int = 500,
        log_max_lookback_minutes: int = 60,
        log_include_previous: bool = True,
        log_mask_emails: bool = True,
        log_mask_public_ips: bool = True,
        log_mask_internal_ips: bool = False,
        log_storage_mode: str = "none",
        external_log_source: str = "none",
        external_log_source_url: str = "",
        external_log_source_tenant_id: str = "",
        external_log_source_timeout_seconds: int = 10,
        manifests_enabled: bool = True,
        max_manifests: int = 80,
        manifest_max_yaml_chars: int = 12000,
        manifest_secret_metadata: bool = True,
        manifest_configmap_values: bool = False,
        manifest_real_names: bool = True,
        slow_refresh_cycles: int = 10,
    ):
        self.hash_salt = hash_salt
        self.max_pods = max(1, min(max_pods, 500))
        self.max_events = max(1, min(max_events, 200))
        self.preserve_namespaces = preserve_namespaces
        self.event_message_mode = event_message_mode if event_message_mode in {"scrubbed", "summary", "none"} else "scrubbed"
        self.logs_enabled = logs_enabled
        self.log_max_lines = max(1, min(log_max_lines, 5000))
        self.log_max_lookback_minutes = max(1, min(log_max_lookback_minutes, 1440))
        self.log_include_previous = log_include_previous
        self.log_mask_emails = log_mask_emails
        self.log_mask_public_ips = log_mask_public_ips
        self.log_mask_internal_ips = log_mask_internal_ips
        self.log_storage_mode = log_storage_mode if log_storage_mode in {"none", "sanitized_evidence", "customer_storage"} else "none"
        self.external_log_source = external_log_source if external_log_source in {"none", "kubernetes", "loki", "opensearch", "splunk", "datadog"} else "none"
        self.external_log_source_url = (external_log_source_url or "").strip().rstrip("/")
        self.external_log_source_tenant_id = (external_log_source_tenant_id or "").strip()
        self.external_log_source_timeout_seconds = max(1, min(int(external_log_source_timeout_seconds or 10), 60))
        self.manifests_enabled = bool(manifests_enabled)
        self.max_manifests = max(1, min(int(max_manifests or 80), 300))
        self.manifest_max_yaml_chars = max(1000, min(int(manifest_max_yaml_chars or 12000), 50000))
        self.manifest_secret_metadata = bool(manifest_secret_metadata)
        self.manifest_configmap_values = bool(manifest_configmap_values)
        # Object names are the one identifier deliberately sent in the clear. An engineer
        # debugging an incident needs "kubectl edit deployment payment-gateway", not an alias
        # they cannot act on. This is an explicit choice, independent of namespace handling,
        # and a customer can turn it off. Secret and ConfigMap *values* are never sent either way.
        self.manifest_real_names = bool(manifest_real_names)
        self.api_client = client.ApiClient()
        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()
        self.autoscaling = client.AutoscalingV1Api()
        self.batch = client.BatchV1Api()
        self.networking = client.NetworkingV1Api()
        self.discovery = client.DiscoveryV1Api()
        self.storage_api = client.StorageV1Api()
        self.metrics = client.CustomObjectsApi()
        self.pod_lookup: dict[str, dict[str, Any]] = {}
        # Platform components, StorageClasses and IngressClasses change on the timescale of a
        # cluster upgrade, not a poll interval. Re-scanning them every cycle spent API-server
        # work on an answer that is almost always identical to the last one.
        self.slow_refresh_cycles = max(1, min(int(slow_refresh_cycles or 10), 240))
        self._cycle = 0
        self._environment_cache: dict[str, Any] | None = None

    def alias(self, kind: str, value: str | None) -> str:
        return alias_identifier(self.hash_salt, kind, value)

    def namespace(self, value: str | None) -> str:
        namespace = value or "default"
        return namespace if self.preserve_namespaces else self.alias("namespace", namespace)

    def object_name(self, kind: str, value: str | None, *, alias_key: str | None = None) -> str:
        """The real Kubernetes name, unless the customer asked for aliases.

        Manifests already honoured manifest_real_names while the pod stream aliased everything
        unconditionally. Because Optimize and the workload tables are built from the pod stream,
        every workload displayed as "privacy alias" no matter how the agent was configured, and
        no setting could turn it off. Both streams now go through this one switch.

        alias_key preserves the composite alias input (namespace/Kind/name) so aliased mode keeps
        producing exactly the identifiers the platform already stores.
        """
        if self.manifest_real_names:
            return str(value or "")
        return self.alias(kind, alias_key if alias_key is not None else value)

    def collect(self) -> tuple[dict[str, Any], int]:
        redactions = 0
        self.pod_lookup = {}
        rs_owner_index = self._replica_set_owner_index()
        pods, pod_redactions = self._collect_pods(rs_owner_index)
        events, event_redactions = self._collect_events()
        raw_nodes = self._list_nodes()
        nodes = self._collect_nodes(raw_nodes)
        platform = self._detect_platform(raw_nodes)
        metrics = self._collect_metrics()
        manifests, manifest_redactions = self._collect_manifests(pods) if self.manifests_enabled else ([], 0)
        # Cheap on every cycle after the first: the scan itself only runs every
        # slow_refresh_cycles, and a newly installed component appears within that window.
        environment = self._environment_snapshot()
        external_log_status = self._external_log_status()
        redactions += pod_redactions + event_redactions + manifest_redactions

        signals = {
            "agent_version": AGENT_VERSION,
            "helm_chart_version": HELM_CHART_VERSION or None,
            "helm_release_name": HELM_RELEASE_NAME or None,
            "helm_release_namespace": HELM_RELEASE_NAMESPACE or None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collection_policy": {
                "identifiers": (
                    "namespace and application controller names preserved; pod, node, container, and object names follow the configured identifier policy"
                    if self.preserve_namespaces else
                    "application controller names preserved; namespace, pod, node, container, and object names follow the configured identifier policy"
                ),
                "event_message_mode": self.event_message_mode,
                "logs_collected": False,
                "logs_on_demand_enabled": self.logs_enabled,
                "log_storage_mode": self.log_storage_mode,
                "external_log_source": self.external_log_source,
                "external_log_source_configured": bool(self.external_log_source_url) if self.external_log_source != "none" else False,
                "external_log_source_status": external_log_status["status"],
                "external_log_source_reason": external_log_status.get("reason"),
                "historical_logs_available": external_log_status["status"] == "available",
                "log_redaction": {
                    "tokens_passwords_and_keys": "always masked",
                    "emails_masked": self.log_mask_emails,
                    "public_ips_masked": self.log_mask_public_ips,
                    "internal_ips_masked": self.log_mask_internal_ips,
                    "max_lines_per_request": self.log_max_lines,
                    "max_lookback_minutes": self.log_max_lookback_minutes,
                    "previous_container_logs_allowed": self.log_include_previous,
                },
                "secrets_accessed": False,
                "secret_values_collected": False,
                "environment_values_collected": False,
                "manifests_collected": self.manifests_enabled,
                "manifest_policy": {
                    "included": "read-only Kubernetes resource specs for investigation" if self.manifests_enabled else "disabled",
                    "secret_values": "never collected",
                    "secret_metadata": self.manifest_secret_metadata,
                    "configmap_values": self.manifest_configmap_values,
                    "environment_values": "redacted",
                    "object_names": "real names, so engineers can act on them" if self.manifest_real_names else "hmac-sha256 aliases",
                    "max_items": self.max_manifests,
                    "max_yaml_chars_per_item": self.manifest_max_yaml_chars,
                },
            },
            "capabilities": [
                "stable_object_identity",
                "correlated_warning_events",
                "workload_manifests",
                "container_status",
                "resource_metrics",
            ] + (["legacy_identity_bridge"] if self.manifest_real_names else []),
            "summary": {
                "pods_observed": len(pods),
                "warning_events_observed": len(events),
                "nodes_observed": len(nodes),
                "metrics_available": metrics["available"],
                "manifests_observed": len(manifests),
            },
            "platform": platform,
            "environment": environment,
            "pods": pods,
            "warning_events": events,
            "nodes": nodes,
            "metrics": metrics,
            "manifests": manifests,
        }
        cleaned, final_redactions = sanitize_value(signals)
        return cleaned, redactions + final_redactions

    def _replica_set_owner_index(self) -> dict[tuple[str, str], tuple[str, str, str | None]]:
        """Maps (namespace, replicaset_name) -> (owner_kind, owner_name), so pods owned by a
        ReplicaSet can resolve up to the real Deployment. Best-effort: replicasets RBAC is only
        granted when manifests are enabled on older installs, so this must never break pod
        collection if the list call is forbidden or otherwise fails.
        """
        index: dict[tuple[str, str], tuple[str, str, str | None]] = {}
        try:
            replica_sets = self.apps.list_replica_set_for_all_namespaces(watch=False, limit=self.max_manifests).items
        except Exception as exc:
            logger.info("ReplicaSet owner lookup unavailable (RBAC or API error): %s", type(exc).__name__)
            return index
        for replica_set in replica_sets:
            owners = replica_set.metadata.owner_references or []
            owner = next((item for item in owners if getattr(item, "controller", False)), owners[0] if owners else None)
            if owner:
                index[(replica_set.metadata.namespace, replica_set.metadata.name)] = (
                    owner.kind, owner.name, getattr(owner, "uid", None)
                )
        return index

    def _collect_pods(self, rs_owner_index: dict[tuple[str, str], tuple[str, str, str | None]] | None = None) -> tuple[list[dict[str, Any]], int]:
        rs_owner_index = rs_owner_index or {}
        items = self.core.list_pod_for_all_namespaces(watch=False, limit=self.max_pods).items
        result = []
        redactions = 0
        for pod in items[: self.max_pods]:
            metadata = pod.metadata
            status = pod.status
            spec = pod.spec
            owners = metadata.owner_references or []
            owner = next((item for item in owners if getattr(item, "controller", False)), owners[0] if owners else None)
            owner_name = getattr(owner, "name", None) or metadata.generate_name or metadata.name
            owner_kind = getattr(owner, "kind", None) or "Pod"
            owner_uid = getattr(owner, "uid", None) or getattr(metadata, "uid", None)

            immediate_owner_kind = None
            immediate_owner_name = None
            if owner_kind == "ReplicaSet":
                resolved = rs_owner_index.get((metadata.namespace, owner_name))
                if resolved:
                    immediate_owner_kind, immediate_owner_name = owner_kind, owner_name
                    owner_kind, owner_name, owner_uid = resolved

            spec_container_lookup = {item.name: item for item in (spec.containers or [])}
            init_spec_lookup = {item.name: item for item in (getattr(spec, "init_containers", None) or [])}
            ephemeral_spec_lookup = {item.name: item for item in (getattr(spec, "ephemeral_containers", None) or [])}

            containers = []
            for container_status in status.container_statuses or []:
                containers.append(self._extract_container_entry(container_status, spec_container_lookup.get(container_status.name)))
                redactions += 1

            init_containers = []
            for container_status in getattr(status, "init_container_statuses", None) or []:
                init_containers.append(self._extract_container_entry(container_status, init_spec_lookup.get(container_status.name)))
                redactions += 1

            ephemeral_containers = []
            for container_status in getattr(status, "ephemeral_container_statuses", None) or []:
                ephemeral_containers.append(self._extract_container_entry(container_status, ephemeral_spec_lookup.get(container_status.name)))
                redactions += 1

            resources = []
            for container in spec.containers or []:
                requests = getattr(container.resources, "requests", None) or {}
                limits = getattr(container.resources, "limits", None) or {}
                resources.append({
                    "container": self.object_name("container", container.name),
                    "requests": {"cpu": requests.get("cpu"), "memory": requests.get("memory")},
                    "limits": {"cpu": limits.get("cpu"), "memory": limits.get("memory")},
                })
                redactions += 1

            conditions = [
                {"type": item.type, "status": item.status, "reason": item.reason}
                for item in (status.conditions or [])
            ]
            namespace_value = self.namespace(metadata.namespace)
            pod_alias = self.object_name("pod", metadata.name)
            # Commands from an older platform snapshot may still carry privacy aliases after a
            # customer enables real object names. Index both forms during the transition so log
            # retrieval remains usable across an agent upgrade.
            legacy_pod_alias = self.alias("pod", metadata.name)
            container_lookup: dict[str, str] = {}
            for item in (spec.containers or []):
                container_lookup[self.object_name("container", item.name)] = item.name
                container_lookup[self.alias("container", item.name)] = item.name
            # Namespace is part of a Kubernetes pod's identity. Keep every
            # namespace/pod pair so an identical pod name in another namespace
            # can never replace the selected target in the on-demand log index.
            self.pod_lookup[f"{namespace_value}/{pod_alias}"] = {
                "namespace": metadata.namespace,
                "namespace_alias": namespace_value,
                "pod": metadata.name,
                "pod_alias": legacy_pod_alias,
                "containers": container_lookup,
            }
            labels_raw = dict(getattr(metadata, "labels", None) or {})
            annotations_raw = dict(getattr(metadata, "annotations", None) or {})
            revision_annotations = {
                key: value
                for key, value in annotations_raw.items()
                if key in ("deployment.kubernetes.io/revision", "app.kubernetes.io/version")
                or key.startswith("argocd.argoproj.io/")
            }

            pod_record = {
                "workload": self.object_name("workload", owner_name, alias_key=f"{metadata.namespace}/{owner_kind}/{owner_name}"),
                # Keep the correlation identity in `workload`, and always provide the real
                # Kubernetes controller name separately for human-facing product surfaces.
                # This is object metadata, never a Secret or ConfigMap value.
                "workload_display_name": str(owner_name),
                "workload_kind": owner_kind,
                "workload_uid": owner_uid,
                "namespace": namespace_value,
                "pod": pod_alias,
                "node": self.object_name("node", spec.node_name),
                "phase": status.phase,
                "started_at": status.start_time.isoformat() if status.start_time else None,
                "containers": containers,
                "init_containers": init_containers,
                "ephemeral_containers": ephemeral_containers,
                "resources": resources,
                "conditions": conditions,
                "uid": getattr(metadata, "uid", None),
                "creation_timestamp": metadata.creation_timestamp.isoformat() if getattr(metadata, "creation_timestamp", None) else None,
                "deletion_timestamp": metadata.deletion_timestamp.isoformat() if getattr(metadata, "deletion_timestamp", None) else None,
                "reason": getattr(status, "reason", None),
                "message": getattr(status, "message", None),
                "pod_ip": getattr(status, "pod_ip", None),
                "host_ip": getattr(status, "host_ip", None),
                "qos_class": getattr(status, "qos_class", None),
                "priority_class_name": getattr(spec, "priority_class_name", None),
                "restart_policy": getattr(spec, "restart_policy", None),
            }
            # The platform used this HMAC identity before real Kubernetes names became the
            # default. During the migration, real-name mode carries both values so historical
            # samples can be joined without exposing anything that aliased mode did not already
            # expose. Aliased mode intentionally remains byte-for-byte unchanged.
            if self.manifest_real_names:
                pod_record["workload_legacy_alias"] = self.alias(
                    "workload", f"{metadata.namespace}/{owner_kind}/{owner_name}"
                )
            if labels_raw:
                pod_record["labels"] = self._redact_manifest_value(labels_raw)
            if annotations_raw:
                pod_record["annotation_keys"] = sorted(str(key) for key in annotations_raw.keys())[:80]
            if revision_annotations:
                pod_record["revision_annotations"] = revision_annotations
            if immediate_owner_kind and immediate_owner_name:
                pod_record["immediate_owner_kind"] = immediate_owner_kind
                pod_record["immediate_owner_name"] = self.object_name(
                    "workload", immediate_owner_name,
                    alias_key=f"{metadata.namespace}/{immediate_owner_kind}/{immediate_owner_name}",
                )

            result.append(pod_record)
            # Only count identifiers that were actually replaced, so the redaction total the
            # customer sees stays truthful when names ship in the clear.
            redactions += 0 if self.manifest_real_names else 4
        return result, redactions

    def _extract_container_entry(self, container_status: Any, spec_container: Any = None) -> dict[str, Any]:
        state = self._container_state(container_status.state)
        last_state_holder = getattr(container_status, "last_state", None)
        previous_state = self._container_state(last_state_holder) if last_state_holder else {"state": "unknown"}
        last_state_fields = (
            {f"last_{key}": value for key, value in previous_state.items()}
            if previous_state.get("state") != "unknown"
            else {}
        )
        return {
            "container": self.object_name("container", container_status.name),
            "ready": bool(container_status.ready),
            "started": bool(getattr(container_status, "started", False)),
            "restarts": int(container_status.restart_count or 0),
            "image": getattr(container_status, "image", None),
            "image_id": getattr(container_status, "image_id", None),
            **state,
            **last_state_fields,
            **self._spec_container_fields(spec_container),
        }

    @staticmethod
    def _spec_container_fields(spec_container: Any) -> dict[str, Any]:
        if spec_container is None:
            return {}
        fields: dict[str, Any] = {}
        command = getattr(spec_container, "command", None)
        if command:
            fields["command"] = list(command)
        args = getattr(spec_container, "args", None)
        if args:
            fields["args"] = list(args)

        probes: dict[str, Any] = {}
        for probe_key, probe_name in (
            ("liveness", "liveness_probe"),
            ("readiness", "readiness_probe"),
            ("startup", "startup_probe"),
        ):
            probe = getattr(spec_container, probe_name, None)
            if not probe:
                continue
            if getattr(probe, "http_get", None):
                probe_type = "httpGet"
            elif getattr(probe, "exec", None):
                probe_type = "exec"
            elif getattr(probe, "tcp_socket", None):
                probe_type = "tcpSocket"
            else:
                probe_type = None
            probes[probe_key] = {
                "type": probe_type,
                "initial_delay_seconds": getattr(probe, "initial_delay_seconds", None),
                "period_seconds": getattr(probe, "period_seconds", None),
                "failure_threshold": getattr(probe, "failure_threshold", None),
            }
        if probes:
            fields["probes"] = probes

        security_context = getattr(spec_container, "security_context", None)
        if security_context:
            fields["security_context"] = {
                "run_as_non_root": getattr(security_context, "run_as_non_root", None),
                "read_only_root_filesystem": getattr(security_context, "read_only_root_filesystem", None),
                "privileged": getattr(security_context, "privileged", None),
            }
        return fields

    @staticmethod
    def _container_state(state_holder: Any) -> dict[str, Any]:
        for state_name in ("waiting", "terminated", "running"):
            state = getattr(state_holder, state_name, None)
            if not state:
                continue
            result = {"state": state_name}
            if state_name != "running":
                result["reason"] = getattr(state, "reason", None)
                result["message"] = getattr(state, "message", None)
                result["exit_code"] = getattr(state, "exit_code", None)
                result["signal"] = getattr(state, "signal", None)
                result["finished_at"] = (
                    state.finished_at.isoformat() if getattr(state, "finished_at", None) else None
                )
            result["started_at"] = (
                state.started_at.isoformat() if getattr(state, "started_at", None) else None
            )
            return result
        return {"state": "unknown"}

    def _collect_events(self) -> tuple[list[dict[str, Any]], int]:
        # Kubernetes applies ``limit`` before the client can sort, so asking for N arbitrary rows
        # could hide a busy cluster's newest warnings behind older Normal events. Rather than
        # accept that trade-off, filter server-side: type=Warning discards the Normal events -
        # the overwhelming majority on any active cluster - before they are ever serialised, so
        # the sort below still sees every warning that exists.
        #
        # resource_version="0" serves the read from the API server's watch cache instead of a
        # quorum read against etcd. Momentarily stale data is irrelevant to an agent that polls
        # once a minute, and it removes the single most expensive read this agent performs.
        items = self.core.list_event_for_all_namespaces(
            watch=False, field_selector="type=Warning", resource_version="0",
        ).items
        warnings = [item for item in items if item.type == "Warning"]
        warnings.sort(key=lambda item: self._event_time(item) or "", reverse=True)
        result = []
        redactions = 0
        for event in warnings[: self.max_events]:
            involved = event.involved_object
            message, count = self._event_message(event, involved)
            redactions += count + 3
            result.append({
                "reason": event.reason,
                "message": message[:2000],
                "object": self.alias("object", f"{involved.kind}/{involved.namespace}/{involved.name}"),
                "object_name": self._event_object_name(involved),
                "kind": involved.kind,
                "namespace": self.namespace(involved.namespace or event.metadata.namespace),
                "count": int(event.count or 1),
                "first_seen": self._event_time(event, prefer_first=True),
                "last_seen": self._event_time(event),
            })
        return result, redactions

    def _event_object_name(self, involved: Any) -> str | None:
        """Alias the involved object's own name using the same bucket the matching first-class
        resource uses elsewhere, so the backend can correlate events by alias equality without
        ever learning real names. Returns None for kinds we don't have a matching bucket for
        rather than fabricating a correlation that wouldn't actually match anything.
        """
        kind = getattr(involved, "kind", None)
        name = getattr(involved, "name", None)
        namespace = getattr(involved, "namespace", None)
        if not kind or not name:
            return None
        if kind == "Pod":
            return self.object_name("pod", name)
        if kind == "Node":
            return self.object_name("node", name)
        if kind in {"ReplicaSet", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}:
            return self.object_name("workload", name, alias_key=f"{namespace}/{kind}/{name}")
        if kind == "PersistentVolumeClaim":
            return self.object_name("pvc", name)
        if kind == "Namespace":
            return self.namespace(name)
        if kind == "Service":
            return self.object_name("service", name)
        if kind == "Ingress":
            return self.object_name("ingress", name)
        if kind == "HorizontalPodAutoscaler":
            return self.object_name("hpa", name)
        return None

    @staticmethod
    def _event_time(event: Any, prefer_first: bool = False) -> str | None:
        if prefer_first:
            value = getattr(event, "first_timestamp", None) or event.metadata.creation_timestamp
        else:
            value = event.last_timestamp or event.event_time or event.metadata.creation_timestamp
        return value.isoformat() if value else None

    def _list_nodes(self) -> list[Any]:
        """Nodes are read once per snapshot and shared by node collection and platform detection.
        Best-effort: a cluster may deny node list to a namespaced agent, and that must not break
        the rest of the snapshot."""
        try:
            return list(self.core.list_node(watch=False, resource_version="0").items)
        except Exception as exc:
            logger.info("Node list unavailable (RBAC or API error): %s", type(exc).__name__)
            return []

    def _detect_platform(self, raw_nodes: list[Any]) -> dict[str, Any]:
        """Fingerprint the cluster distribution (EKS, GKE, AKS, OpenShift, kind, ...) from
        read-only signals. Ships the derived classification, not raw providerIDs or regions, so
        no new identifying data leaves the cluster."""
        provider_ids: list[str] = []
        label_keys: set[str] = set()
        kubelet_versions: list[str] = []
        os_images: list[str] = []
        node_names: list[str] = []
        for node in raw_nodes:
            spec = getattr(node, "spec", None)
            provider_id = getattr(spec, "provider_id", None)
            if provider_id:
                provider_ids.append(provider_id)
            metadata = getattr(node, "metadata", None)
            if metadata:
                label_keys.update((getattr(metadata, "labels", None) or {}).keys())
                if getattr(metadata, "name", None):
                    node_names.append(metadata.name)
            info = getattr(getattr(node, "status", None), "node_info", None)
            if info:
                if info.kubelet_version:
                    kubelet_versions.append(info.kubelet_version)
                if getattr(info, "os_image", None):
                    os_images.append(info.os_image)

        api_groups: set[str] = set()
        try:
            groups = client.ApisApi(self.api_client).get_api_versions().groups
            api_groups = {group.name for group in (groups or []) if getattr(group, "name", None)}
        except Exception as exc:
            logger.info("Platform API discovery unavailable: %s", type(exc).__name__)

        return classify_platform(
            provider_ids=provider_ids,
            label_keys=label_keys,
            kubelet_versions=kubelet_versions,
            os_images=os_images,
            api_groups=api_groups,
            node_names=node_names,
        )

    def _collect_nodes(self, raw_nodes: list[Any]) -> list[dict[str, Any]]:
        result = []
        for node in raw_nodes:
            conditions = {item.type: item.status for item in (node.status.conditions or [])}
            capacity = node.status.capacity or {}
            allocatable = node.status.allocatable or {}
            info = node.status.node_info
            result.append({
                "node": self.object_name("node", node.metadata.name),
                "ready": conditions.get("Ready") == "True",
                "pressure": {
                    "memory": conditions.get("MemoryPressure") == "True",
                    "disk": conditions.get("DiskPressure") == "True",
                    "pid": conditions.get("PIDPressure") == "True",
                },
                "capacity": {"cpu": capacity.get("cpu"), "memory": capacity.get("memory")},
                "allocatable": {"cpu": allocatable.get("cpu"), "memory": allocatable.get("memory")},
                "kubernetes_version": info.kubelet_version if info else None,
                "operating_system": info.operating_system if info else None,
                "architecture": info.architecture if info else None,
                "taints": [
                    {"key": taint.key, "value": taint.value, "effect": taint.effect}
                    for taint in (getattr(getattr(node, "spec", None), "taints", None) or [])
                ],
            })
        return result

    def fetch_deployment_inventory(self, requested_categories: list[str] | None = None) -> tuple[dict[str, Any], int]:
        """Collect a small, read-only inventory for deployment compatibility checks.

        The command intentionally cannot return logs, Secret/ConfigMap data, environment
        values, or manifest bodies. Each category is independently best-effort so one RBAC
        denial does not hide the facts that the agent is allowed to read.
        """
        allowed = {"platform", "namespaces", "storage", "networking", "argocd", "operators", "capacity"}
        requested = {str(item) for item in (requested_categories or []) if str(item) in allowed} or allowed
        result: dict[str, Any] = {
            "coverage": {item: False for item in sorted(requested)},
            "sources": ["live agent deployment inventory"],
        }
        raw_namespaces: list[str] = []
        raw_nodes: list[Any] = []

        if requested & {"namespaces", "argocd"}:
            try:
                raw_namespaces = [item.metadata.name for item in self.core.list_namespace(watch=False).items if item.metadata.name]
                if "namespaces" in requested:
                    result["namespaces"] = sorted({self.namespace(name) for name in raw_namespaces}, key=str.lower)[:200]
                    result["coverage"]["namespaces"] = True
            except Exception as exc:
                logger.info("Deployment inventory namespace list unavailable: %s", type(exc).__name__)

        if requested & {"platform", "capacity"}:
            raw_nodes = self._list_nodes()
            if "platform" in requested and raw_nodes:
                result["platform"] = self._detect_platform(raw_nodes)
                result["coverage"]["platform"] = True
            if "capacity" in requested and raw_nodes:
                collected_nodes = self._collect_nodes(raw_nodes)
                result["nodes"] = {
                    "total": len(collected_nodes),
                    "ready": sum(1 for item in collected_nodes if item.get("ready") is True),
                }
                result["coverage"]["capacity"] = True

        if "storage" in requested:
            try:
                classes = self.storage_api.list_storage_class(watch=False).items
                safe_classes = []
                default_class = None
                for item in classes:
                    name = getattr(item.metadata, "name", None)
                    if not name:
                        continue
                    annotations = getattr(item.metadata, "annotations", None) or {}
                    is_default = str(annotations.get("storageclass.kubernetes.io/is-default-class", "")).lower() == "true" or str(annotations.get("storageclass.beta.kubernetes.io/is-default-class", "")).lower() == "true"
                    safe_classes.append(name)
                    if is_default:
                        default_class = name
                result["storage_classes"] = sorted(set(safe_classes), key=str.lower)[:100]
                result["default_storage_class"] = default_class
                result["coverage"]["storage"] = True
            except Exception as exc:
                logger.info("Deployment inventory StorageClass list unavailable: %s", type(exc).__name__)

        if "networking" in requested:
            try:
                classes = self.networking.list_ingress_class(watch=False).items
                result["ingress_classes"] = sorted({item.metadata.name for item in classes if item.metadata.name}, key=str.lower)[:100]
                result["coverage"]["networking"] = True
            except Exception as exc:
                logger.info("Deployment inventory IngressClass list unavailable: %s", type(exc).__name__)

        if requested & {"argocd", "operators"}:
            recognized = {
                "argocd": ("argocd", "argo-cd", "argo cd"),
                "cloudnative-pg": ("cloudnative-pg", "cnpg"),
                "postgres-operator": ("postgres-operator", "zalando-postgres"),
                "mongodb-operator": ("mongodb-operator",),
                "kyverno": ("kyverno",),
                "external-secrets": ("external-secrets",),
                "cert-manager": ("cert-manager",),
            }
            searchable: list[str] = list(raw_namespaces)
            apps_read = False
            try:
                searchable.extend(item.metadata.name for item in self.apps.list_deployment_for_all_namespaces(watch=False).items if item.metadata.name)
                searchable.extend(item.metadata.name for item in self.apps.list_stateful_set_for_all_namespaces(watch=False).items if item.metadata.name)
                apps_read = True
            except Exception as exc:
                logger.info("Deployment inventory workload list unavailable: %s", type(exc).__name__)
            text = " ".join(searchable).lower()
            detected = [name for name, needles in recognized.items() if any(needle in text for needle in needles)]
            if "argocd" in requested and (raw_namespaces or apps_read):
                argo_namespace = next((self.namespace(name) for name in raw_namespaces if "argocd" in name.lower()), None)
                result["argo_cd"] = {"installed": "argocd" in detected, "namespace": argo_namespace}
                result["coverage"]["argocd"] = True
            if "operators" in requested and apps_read:
                result["operators"] = sorted(item for item in detected if item != "argocd")
                result["crds"] = []
                result["coverage"]["operators"] = True

        cleaned, redactions = sanitize_value(result)
        return cleaned, redactions

    def _collect_metrics(self) -> dict[str, Any]:
        try:
            pod_metrics = self.metrics.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods")
            node_metrics = self.metrics.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes")
        except Exception as exc:
            logger.info("Kubernetes Metrics API unavailable: %s", type(exc).__name__)
            return {"available": False, "pods": [], "nodes": []}

        pods = []
        for pod in pod_metrics.get("items", [])[: self.max_pods]:
            metadata = pod.get("metadata", {})
            pods.append({
                "pod": self.object_name("pod", metadata.get("name")),
                "namespace": self.namespace(metadata.get("namespace")),
                "containers": [
                    {
                        "container": self.object_name("container", item.get("name")),
                        "cpu": item.get("usage", {}).get("cpu"),
                        "memory": item.get("usage", {}).get("memory"),
                    }
                    for item in pod.get("containers", [])
                ],
            })
        nodes = [
            {
                "node": self.object_name("node", item.get("metadata", {}).get("name")),
                "cpu": item.get("usage", {}).get("cpu"),
                "memory": item.get("usage", {}).get("memory"),
            }
            for item in node_metrics.get("items", [])
        ]
        return {"available": True, "pods": pods, "nodes": nodes}

    # Well-known platform components, matched against Service names and the standard
    # app.kubernetes.io labels. Order does not decide a winner: every pattern a name matches
    # is recorded, so "grafana-loki" reports Grafana *and* Loki rather than whichever pattern
    # happens to be listed first.
    _KNOWN_COMPONENTS = (
        ("argocd", "Argo CD (GitOps)"),
        ("argo-cd", "Argo CD (GitOps)"),
        ("flux", "Flux (GitOps)"),
        ("ingress-nginx", "NGINX Ingress Controller"),
        ("nginx-ingress", "NGINX Ingress Controller"),
        ("traefik", "Traefik Ingress Controller"),
        ("haproxy-ingress", "HAProxy Ingress Controller"),
        ("istio", "Istio Service Mesh"),
        ("kong", "Kong Gateway"),
        ("contour", "Contour Ingress Controller"),
        ("router-default", "OpenShift Router"),
        ("cert-manager", "cert-manager"),
        ("external-dns", "ExternalDNS"),
        ("external-secrets", "External Secrets Operator"),
        ("prometheus", "Prometheus"),
        ("alertmanager", "Alertmanager"),
        ("grafana", "Grafana"),
        ("loki", "Loki"),
        ("metrics-server", "Kubernetes Metrics Server"),
        ("postgres-operator", "Zalando Postgres Operator"),
        ("strimzi", "Strimzi Kafka Operator"),
        ("rabbitmq-cluster-operator", "RabbitMQ Cluster Operator"),
        ("velero", "Velero"),
        ("keda", "KEDA"),
        ("kyverno", "Kyverno"),
        ("gatekeeper", "OPA Gatekeeper"),
    )

    def _environment_snapshot(self) -> dict[str, Any]:
        """Return the component scan, refreshing it only every slow_refresh_cycles.

        The cached value is returned verbatim in between, so the snapshot shape never changes -
        consumers cannot tell a cached cycle from a fresh one.
        """
        self._cycle += 1
        due = self._environment_cache is None or (self._cycle % self.slow_refresh_cycles) == 1
        if due or self.slow_refresh_cycles == 1:
            self._environment_cache = self._collect_environment()
        return self._environment_cache

    def _collect_environment(self) -> dict[str, Any]:
        """Which well-known platform components actually run in this cluster.

        Detection reads Services rather than workloads because charts routinely give the
        Deployment a generic name ("logs-gateway") while the Service keeps the stable product
        name and the standard app.kubernetes.io labels. Names and labels are read raw, before
        aliasing, so privacy settings cannot manufacture a false negative.

        component_scan reports whether the scan actually ran. Without it the platform cannot
        tell "this cluster has no Loki" apart from "the agent was never allowed to look" - both
        reached the customer as "not detected", which is only true in one of those cases.
        """
        components: list[dict[str, str]] = []
        seen_components: set[str] = set()
        services_scanned = False
        services_scan_reason: str | None = None
        try:
            for service in self.core.list_service_for_all_namespaces(watch=False, resource_version="0").items:
                metadata = service.metadata
                labels = metadata.labels or {}
                candidates = " ".join(str(value) for value in (
                    metadata.name,
                    labels.get("app.kubernetes.io/name"),
                    labels.get("app.kubernetes.io/instance"),
                    labels.get("app"),
                ) if value).lower()
                for pattern, label in self._KNOWN_COMPONENTS:
                    if pattern in candidates and label not in seen_components:
                        seen_components.add(label)
                        components.append({
                            "component": label,
                            "namespace": self.namespace(metadata.namespace),
                            "workload": self.object_name("service", metadata.name),
                            "detected_from": "Service",
                        })
            services_scanned = True
        except Exception as exc:
            services_scan_reason = type(exc).__name__
            logger.info("Service API unavailable for component detection: %s", services_scan_reason)

        return {
            "detected_components": components,
            # Compatibility alias for older platform versions.
            "components": components,
            "component_scan": {
                "services_scanned": services_scanned,
                "reason": services_scan_reason,
            },
        }

    def _collect_manifests(self, pods: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], int]:
        """Collect safe, redacted resource specs for AI investigation.

        This intentionally does not read Secret values or ConfigMap values by
        default. The output is meant to explain *how* workloads are configured:
        refs, selectors, resources, probes, service/ingress/storage wiring, and
        GitOps objects. It is not a raw cluster backup.
        """
        collectors: list[tuple[str, Any]] = [
            ("Deployment", lambda: self.apps.list_deployment_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("StatefulSet", lambda: self.apps.list_stateful_set_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("DaemonSet", lambda: self.apps.list_daemon_set_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("Job", lambda: self.batch.list_job_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("CronJob", lambda: self.batch.list_cron_job_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("Service", lambda: self.core.list_service_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("EndpointSlice", lambda: self.discovery.list_endpoint_slice_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("Ingress", lambda: self.networking.list_ingress_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("NetworkPolicy", lambda: self.networking.list_network_policy_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("PersistentVolumeClaim", lambda: self.core.list_persistent_volume_claim_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("PersistentVolume", lambda: self.core.list_persistent_volume(watch=False, limit=self.max_manifests).items),
            ("StorageClass", lambda: self.storage_api.list_storage_class(watch=False, limit=self.max_manifests).items),
            ("HorizontalPodAutoscaler", lambda: self.autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces(watch=False, limit=self.max_manifests).items),
            ("ConfigMap", lambda: self.core.list_config_map_for_all_namespaces(watch=False, limit=self.max_manifests).items),
        ]
        if self.manifest_secret_metadata:
            collectors.append(("Secret", lambda: self.core.list_secret_for_all_namespaces(watch=False, limit=self.max_manifests).items))

        buckets: list[list[tuple[dict[str, Any], int]]] = []
        redactions = 0
        for kind, loader in collectors:
            try:
                items = loader()
            except Exception as exc:
                logger.info("Manifest collector skipped %s: %s", kind, type(exc).__name__)
                continue
            bucket: list[tuple[dict[str, Any], int]] = []
            for obj in items:
                item, item_redactions = self._manifest_item(kind, obj)
                if item:
                    bucket.append((item, item_redactions))
            if bucket:
                buckets.append(bucket)

        pod_rows = pods or []
        priority_refs = {
            (pod.get("namespace"), pod.get("workload"))
            for pod in pod_rows
            if pod.get("phase") not in {"Running", "Succeeded"}
            or not (pod.get("containers") or [])
            or any(not container.get("ready") for container in (pod.get("containers") or []))
        }
        priority_namespaces = {namespace for namespace, _workload in priority_refs if namespace}
        dependency_kinds = {"Service", "EndpointSlice", "NetworkPolicy", "PersistentVolumeClaim", "ConfigMap", "Secret"}

        selected: list[tuple[dict[str, Any], int]] = []
        remaining: list[list[tuple[dict[str, Any], int]]] = []
        for bucket in buckets:
            rest = []
            for entry in bucket:
                item = entry[0]
                relevant = (
                    (item.get("namespace"), item.get("workload_ref")) in priority_refs
                    or (item.get("namespace") in priority_namespaces and item.get("kind") in dependency_kinds)
                )
                if relevant and len(selected) < self.max_manifests:
                    selected.append(entry)
                else:
                    rest.append(entry)
            if rest:
                remaining.append(rest)

        # Deterministic round-robin fair share. A cluster with 80 Deployments can no longer
        # consume the whole payload before Service/network/storage collectors get one slot.
        index = 0
        while len(selected) < self.max_manifests and remaining:
            bucket = remaining[index % len(remaining)]
            selected.append(bucket.pop(0))
            if not bucket:
                remaining.remove(bucket)
                index = 0
            else:
                index += 1

        result = [item for item, _count in selected]
        redactions = sum(count for _item, count in selected)
        return result, redactions

    def _manifest_item(self, kind: str, obj: Any) -> tuple[dict[str, Any] | None, int]:
        raw = self.api_client.sanitize_for_serialization(obj)
        if not isinstance(raw, dict):
            return None, 0
        metadata = raw.get("metadata") or {}
        name = metadata.get("name")
        namespace = metadata.get("namespace")
        safe_name = self._manifest_name(kind.lower(), name)
        safe_namespace = self.namespace(namespace) if namespace else None

        safe = {
            "apiVersion": raw.get("apiVersion") or self._api_version_for_kind(kind),
            "kind": kind,
            "metadata": self._safe_manifest_metadata(kind, metadata),
        }
        spec = self._safe_manifest_spec(kind, raw)
        if spec:
            safe["spec"] = spec

        yaml_text = yaml.safe_dump(safe, sort_keys=False, allow_unicode=True)
        # Scrub each identifier according to its own setting, so choosing real object names does
        # not silently re-expose namespaces, and aliasing namespaces does not strip wanted names.
        identifiers = []
        if not self.manifest_real_names:
            identifiers.append(name or "")
        if not self.preserve_namespaces:
            identifiers.append(namespace or "")
        yaml_text, text_redactions = scrub_text(yaml_text, identifiers)
        if len(yaml_text) > self.manifest_max_yaml_chars:
            yaml_text = yaml_text[: self.manifest_max_yaml_chars] + "\n# [TRUNCATED_BY_KREVOPILOT_AGENT]\n"

        item = {
            "kind": kind,
            "name": safe_name,
            "object": safe_name,
            "namespace": safe_namespace,
            "yaml": yaml_text,
            "source": "agent",
        }
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}:
            item["workload"] = safe_name
            item["workload_kind"] = kind
            # Must stay byte-identical to the pod stream's "workload" field so a manifest can be
            # matched to the pod it belongs to. Both sides go through object_name, so they agree
            # in real-name mode and in aliased mode alike.
            item["workload_ref"] = self.object_name("workload", name, alias_key=f"{namespace}/{kind}/{name}")
            if self.manifest_real_names:
                # Temporary migration bridge. Keep through at least two published agent
                # releases after the SaaS identity merge is live, then remove only after
                # telemetry confirms no supported agent still depends on it.
                item["workload_legacy_alias"] = self.alias("workload", f"{namespace}/{kind}/{name}")
        # The owner lets the platform walk ReplicaSet -> Deployment, which is the object an
        # engineer actually edits: a change to the ReplicaSet is reverted by its Deployment.
        owner = self._manifest_owner(metadata)
        if owner:
            item["owner"] = owner
        return item, text_redactions

    def _manifest_owner(self, metadata: dict[str, Any]) -> dict[str, Any] | None:
        for reference in metadata.get("ownerReferences") or []:
            kind = reference.get("kind")
            name = reference.get("name")
            if not kind or not name:
                continue
            namespace = metadata.get("namespace")
            owner = {
                "kind": kind,
                "name": self._manifest_name(str(kind).lower(), name),
                "workload_ref": self.object_name("workload", name, alias_key=f"{namespace}/{kind}/{name}"),
            }
            if self.manifest_real_names:
                owner["workload_legacy_alias"] = self.alias("workload", f"{namespace}/{kind}/{name}")
            return owner
        return None

    def _manifest_name(self, kind: str, value: str | None) -> str:
        """Display name for an object.

        Real by default so an engineer can act on it directly. Namespace handling is a separate
        decision, so this deliberately does not key off preserve_namespaces.
        """
        return str(value or "") if self.manifest_real_names else self.alias(kind, value)

    def _safe_manifest_metadata(self, kind: str, metadata: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self._manifest_name(kind.lower(), metadata.get("name")),
        }
        if metadata.get("namespace"):
            result["namespace"] = self.namespace(metadata.get("namespace"))
        labels = metadata.get("labels") or {}
        if labels:
            result["labels"] = self._redact_manifest_value(labels)
        annotations = metadata.get("annotations") or {}
        if annotations:
            result["annotationKeys"] = sorted(str(key) for key in annotations.keys())[:80]
        for timestamp_key in ("creationTimestamp",):
            if metadata.get(timestamp_key):
                result[timestamp_key] = metadata.get(timestamp_key)
        return result

    def _safe_manifest_spec(self, kind: str, raw: dict[str, Any]) -> dict[str, Any]:
        if kind == "Secret":
            data = raw.get("data") or {}
            string_data = raw.get("stringData") or {}
            return {
                "type": raw.get("type"),
                "dataKeyCount": len(data) if isinstance(data, dict) else 0,
                "stringDataKeyCount": len(string_data) if isinstance(string_data, dict) else 0,
            }
        if kind == "ConfigMap":
            data = raw.get("data") or {}
            binary_data = raw.get("binaryData") or {}
            spec = {
                "dataKeys": sorted(str(key) for key in data.keys())[:80] if isinstance(data, dict) else [],
                "binaryDataKeys": sorted(str(key) for key in binary_data.keys())[:80] if isinstance(binary_data, dict) else [],
            }
            if self.manifest_configmap_values and isinstance(data, dict):
                spec["data"] = self._redact_manifest_value(data)
            return spec

        spec = raw.get("spec") or {}
        if not isinstance(spec, dict):
            return {}
        cleaned = self._redact_manifest_value(spec)
        if kind == "Service" and isinstance(cleaned, dict):
            cleaned.pop("clusterIP", None)
            cleaned.pop("clusterIPs", None)
            cleaned.pop("externalIPs", None)
            cleaned.pop("loadBalancerIP", None)
        return cleaned

    def _redact_manifest_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, child in value.items():
                key_str = str(key)
                lower = key_str.lower()
                if lower in {"managedfields", "status"}:
                    continue
                if (
                    not self.manifest_real_names
                    and lower in {"image", "command", "args"}
                    and child not in (None, "", [])
                ):
                    result[key_str] = "[REDACTED_CONTAINER_SPEC]"
                    continue
                if lower in {"data", "binarydata", "stringdata"} and isinstance(child, dict):
                    result[f"{key_str}Keys"] = sorted(str(item) for item in child.keys())[:80]
                    continue
                if lower == "value":
                    result[key_str] = "REDACTED_ENV_VALUE"
                    continue
                result[key_str] = self._redact_manifest_value(child)
            return result
        if isinstance(value, list):
            return [self._redact_manifest_value(item) for item in value]
        if isinstance(value, str):
            cleaned, _count = scrub_text(value)
            return cleaned
        return value

    @staticmethod
    def _api_version_for_kind(kind: str) -> str:
        return {
            "Deployment": "apps/v1",
            "StatefulSet": "apps/v1",
            "DaemonSet": "apps/v1",
            "ReplicaSet": "apps/v1",
            "Job": "batch/v1",
            "CronJob": "batch/v1",
            "Service": "v1",
            "Ingress": "networking.k8s.io/v1",
            "NetworkPolicy": "networking.k8s.io/v1",
            "PersistentVolumeClaim": "v1",
            "PersistentVolume": "v1",
            "StorageClass": "storage.k8s.io/v1",
            "HorizontalPodAutoscaler": "autoscaling/v1",
            "ConfigMap": "v1",
            "Secret": "v1",
        }.get(kind, "v1")

    def _event_message(self, event: Any, involved: Any) -> tuple[str, int]:
        if self.event_message_mode == "none":
            return "", 0
        if self.event_message_mode == "summary":
            reason = getattr(event, "reason", None) or "Warning"
            kind = getattr(involved, "kind", None) or "Object"
            return f"{kind} warning reason: {reason}", 0
        return scrub_text(
            event.message,
            [event.metadata.name, event.metadata.namespace, involved.name, involved.namespace],
        )

    def fetch_pod_logs(
        self,
        namespace: str,
        pod: str,
        container: str | None = None,
        *,
        previous: bool = False,
        tail_lines: int = 200,
        since_seconds: int | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Fetch and redact pod logs for a future on-demand command channel.

        This method is intentionally not called during regular snapshots. Pilot
        should request it only for a specific user-authorized pod/log view.
        """
        if not self.logs_enabled:
            raise RuntimeError("On-demand logs are disabled by agent policy")
        if previous and not self.log_include_previous:
            raise RuntimeError("Previous container logs are disabled by agent policy")

        resolved = self._resolve_log_target(namespace, pod, container)
        safe_tail = max(1, min(int(tail_lines or 200), self.log_max_lines))
        max_since = self.log_max_lookback_minutes * 60
        # An explicit number is bounded by policy. None deliberately means
        # "no Kubernetes time cutoff": this is required for completed/failed
        # Job pods whose retained logs may be older than the normal live-log
        # window. The line count remains capped, so the response is bounded.
        safe_since = (
            max(1, min(int(since_seconds), max_since))
            if since_seconds not in (None, "")
            else None
        )
        if self.external_log_source == "loki" and not previous:
            loki_since = safe_since or max_since
            raw = self._fetch_loki_logs(
                resolved["namespace"],
                resolved["pod"],
                resolved["container"],
                safe_tail,
                loki_since,
            )
            source = "loki"
        else:
            raw = self.core.read_namespaced_pod_log(
                name=resolved["pod"],
                namespace=resolved["namespace"],
                container=resolved["container"],
                previous=previous,
                tail_lines=safe_tail,
                since_seconds=safe_since,
                timestamps=True,
            )
            source = "kubernetes"

        cleaned, redactions = scrub_log_text(
            raw,
            [resolved["namespace"], resolved["pod"], resolved["container"] or ""],
            mask_emails=self.log_mask_emails,
            mask_public_ips=self.log_mask_public_ips,
            mask_internal_ips=self.log_mask_internal_ips,
        )
        return {
            "namespace": self.namespace(resolved["namespace"]),
            "pod": self.object_name("pod", resolved["pod"]),
            "container": self.object_name("container", resolved["container"]) if resolved["container"] else None,
            "previous": previous,
            "tail_lines": safe_tail,
            "since_seconds": safe_since,
            "storage_mode": self.log_storage_mode,
            "source": source,
            "logs": cleaned,
            "redacted": redactions > 0,
        }, redactions

    def _external_log_status(self) -> dict[str, Any]:
        """Whether historical log queries will actually work - not merely whether someone set
        the flags. "Configured" and "reachable" are different answers with different fixes, so
        the platform is given both instead of inferring one from the other.

        The failure reason deliberately omits the endpoint itself: a customer-supplied URL can
        carry embedded credentials, and this value is stored with the snapshot.
        """
        if self.external_log_source != "loki":
            return {"status": "not_configured", "reason": "not configured"}
        if not self.external_log_source_url:
            return {"status": "unavailable", "reason": "Loki URL is missing"}
        try:
            response = requests.get(
                urljoin(self.external_log_source_url + "/", "loki/api/v1/labels"),
                headers=self._loki_headers(),
                timeout=(3, self.external_log_source_timeout_seconds),
            )
            response.raise_for_status()
        except Exception as exc:
            return {"status": "unavailable", "reason": f"{type(exc).__name__} while probing the configured Loki endpoint"}
        return {"status": "available", "reason": None}

    def _fetch_loki_logs(
        self,
        namespace: str,
        pod: str,
        container: str | None,
        tail_lines: int,
        since_seconds: int,
    ) -> str:
        if not self.external_log_source_url:
            raise RuntimeError("Loki log source is enabled but EXTERNAL_LOG_SOURCE_URL is empty")

        selector_parts = [f'namespace="{self._escape_loki_label(namespace)}"', f'pod="{self._escape_loki_label(pod)}"']
        if container:
            selector_parts.append(f'container="{self._escape_loki_label(container)}"')
        query = "{" + ",".join(selector_parts) + "}"
        end_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
        start_ns = end_ns - int(since_seconds * 1_000_000_000)
        response = requests.get(
            self._loki_query_range_url(),
            params={
                "query": query,
                "start": str(start_ns),
                "end": str(end_ns),
                "limit": str(tail_lines),
                "direction": "backward",
            },
            headers=self._loki_headers(),
            timeout=(3, self.external_log_source_timeout_seconds),
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            raise RuntimeError(f"Loki query failed: {payload.get('error') or payload.get('status')}")

        rows: list[tuple[int, str]] = []
        for stream in payload.get("data", {}).get("result", []) or []:
            for value in stream.get("values", []) or []:
                if len(value) != 2:
                    continue
                try:
                    timestamp_ns = int(value[0])
                except (TypeError, ValueError):
                    timestamp_ns = 0
                rows.append((timestamp_ns, str(value[1])))

        rows.sort(key=lambda item: item[0])
        if not rows:
            return "No Loki logs matched this pod/container/time window."
        return "\n".join(self._format_loki_line(timestamp_ns, line) for timestamp_ns, line in rows[-tail_lines:])

    def _loki_query_range_url(self) -> str:
        if self.external_log_source_url.endswith("/loki/api/v1/query_range"):
            return self.external_log_source_url
        return urljoin(self.external_log_source_url + "/", "loki/api/v1/query_range")

    def _loki_headers(self) -> dict[str, str]:
        if not self.external_log_source_tenant_id:
            return {}
        return {"X-Scope-OrgID": self.external_log_source_tenant_id}

    @staticmethod
    def _escape_loki_label(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _format_loki_line(timestamp_ns: int, line: str) -> str:
        if timestamp_ns <= 0:
            return line
        timestamp = datetime.fromtimestamp(timestamp_ns / 1_000_000_000, tz=timezone.utc).isoformat()
        return f"{timestamp} {line}"

    def _resolve_log_target(self, namespace: str, pod: str, container: str | None) -> dict[str, str | None]:
        matches: list[dict[str, Any]] = []
        for candidate in self.pod_lookup.values():
            pod_matches = pod in {candidate["pod"], candidate.get("pod_alias")}
            namespace_matches = namespace in {candidate["namespace"], candidate["namespace_alias"]}
            if pod_matches and namespace_matches:
                matches.append(candidate)

        if len(matches) != 1:
            if len(matches) > 1:
                raise RuntimeError("Requested namespace/pod target is ambiguous in the agent's latest in-memory pod index")
            raise RuntimeError("Requested namespace/pod target is not in the agent's latest in-memory pod index")

        match = matches[0]
        real_container = match["containers"].get(container, container) if container else None
        if container and real_container not in set(match["containers"].values()):
            raise RuntimeError("Requested container is not present in the selected namespace/pod")
        return {"namespace": match["namespace"], "pod": match["pod"], "container": real_container}
