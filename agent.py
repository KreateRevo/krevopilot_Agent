import json
import hashlib
import logging
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone
from threading import Event
from urllib.parse import urlparse

import requests

from collector import AGENT_VERSION, ClusterCollector, load_kubernetes_config

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("krevopilot.agent")
stop_event = Event()


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return value


def positive_int(name: str, default: int, maximum: int) -> int:
    try:
        raw = os.getenv(name, str(default)).strip()
        value = int(raw or str(default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < 1 or value > maximum:
        raise RuntimeError(f"{name} must be between 1 and {maximum}")
    return value


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_choice(name: str, default: str, allowed: set[str]) -> str:
    value = os.getenv(name, default).strip().lower()
    if value not in allowed:
        raise RuntimeError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return value


def validate_platform_url(url: str) -> str:
    parsed = urlparse(url)
    allow_http = os.getenv("ALLOW_INSECURE_HTTP", "false").lower() == "true"
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("PLATFORM_URL must be an absolute http(s) URL")
    if parsed.scheme != "https" and not allow_http:
        raise RuntimeError("PLATFORM_URL must use HTTPS unless ALLOW_INSECURE_HTTP=true")
    return url.rstrip("/")


def install_signal_handlers() -> None:
    def stop(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


def deliver(session: requests.Session, endpoint: str, agent_key: str, payload: dict, verify_tls: bool) -> dict:
    response = session.post(
        endpoint,
        json=payload,
        headers={
            "X-Agent-Key": agent_key,
            "User-Agent": f"KrevoPilot-Agent/{AGENT_VERSION}",
            "Content-Type": "application/json",
        },
        timeout=(5, 20),
        verify=verify_tls,
    )
    response.raise_for_status()
    return response.json()


def fetch_commands(session: requests.Session, platform_url: str, agent_key: str, verify_tls: bool) -> list[dict]:
    response = session.get(
        f"{platform_url}/api/agent/commands",
        headers={
            "X-Agent-Key": agent_key,
            "User-Agent": f"KrevoPilot-Agent/{AGENT_VERSION}",
        },
        timeout=(5, 20),
        verify=verify_tls,
    )
    response.raise_for_status()
    return response.json()


def submit_command_result(session: requests.Session, platform_url: str, agent_key: str, command_id: int, payload: dict, verify_tls: bool) -> None:
    response = session.post(
        f"{platform_url}/api/agent/commands/{command_id}/result",
        json=payload,
        headers={
            "X-Agent-Key": agent_key,
            "User-Agent": f"KrevoPilot-Agent/{AGENT_VERSION}",
            "Content-Type": "application/json",
        },
        timeout=(5, 20),
        verify=verify_tls,
    )
    response.raise_for_status()


def handle_commands(session: requests.Session, platform_url: str, agent_key: str, collector: ClusterCollector, verify_tls: bool) -> None:
    commands = fetch_commands(session, platform_url, agent_key, verify_tls)
    for command in commands:
        command_id = int(command.get("id"))
        command_type = command.get("type")
        payload = command.get("payload") or {}
        try:
            if command_type == "pod_logs":
                raw_since_seconds = payload.get("since_seconds")
                result, redactions = collector.fetch_pod_logs(
                    payload.get("namespace", ""),
                    payload.get("pod", ""),
                    payload.get("container") or None,
                    previous=bool(payload.get("previous", False)),
                    tail_lines=int(payload.get("tail_lines", 200)),
                    # An omitted/JSON-null lookback means "use the collector's
                    # configured maximum". This is required for completed Job
                    # pods whose useful logs may be older than the default window.
                    since_seconds=(
                        int(raw_since_seconds)
                        if raw_since_seconds not in (None, "")
                        else None
                    ),
                )
            elif command_type == "deployment_inventory":
                result, redactions = collector.fetch_deployment_inventory(payload.get("categories") or [])
            else:
                raise RuntimeError(f"Unsupported command type: {command_type}")
            result["redactions"] = redactions
            submit_command_result(session, platform_url, agent_key, command_id, {"status": "completed", "result": result}, verify_tls)
            logger.info("Agent command completed id=%s type=%s redactions=%s", command_id, command_type, redactions)
        except Exception as exc:
            submit_command_result(
                session,
                platform_url,
                agent_key,
                command_id,
                {"status": "failed", "result": {}, "error": str(exc)[:4000]},
                verify_tls,
            )
            logger.warning("Agent command failed id=%s type=%s error=%s", command_id, command_type, exc)


def stable_cluster_identity_source(collector: ClusterCollector, configured_alias: str) -> tuple[str, str]:
    """Return a stable, non-secret source string used only for local HMAC aliasing.

    The Helm value CLUSTER_ID is a customer-friendly alias. It must not be the
    physical cluster identity, because users can rename it or accidentally paste
    a different alias during an upgrade. Kubernetes namespace UIDs are stable for
    a cluster lifetime and safe to hash before sending to KrevoPilot.
    """
    try:
        namespace = collector.core.read_namespace("kube-system")
        uid = getattr(namespace.metadata, "uid", "") or ""
        if uid:
            return f"kube-system-uid:{uid}", "kube-system-namespace-uid-v1"
    except Exception as exc:  # pragma: no cover - defensive fallback for unusual RBAC
        logger.warning("Could not read kube-system namespace UID for stable cluster identity: %s", type(exc).__name__)
    return f"configured-alias:{configured_alias}", "configured-alias-fallback"


def stable_cluster_identifier(identity_source: str, identity_scheme: str) -> str:
    """Create a physical cluster ID that is independent of credentials and privacy salt."""
    digest = hashlib.sha256(identity_source.encode("utf-8")).hexdigest()[:24]
    prefix = "cluster" if identity_scheme == "kube-system-namespace-uid-v1" else "cluster-fallback"
    return f"{prefix}-{digest}"


def run() -> None:
    platform_url = validate_platform_url(required_env("PLATFORM_URL"))
    agent_key = required_env("AGENT_KEY")
    cluster_name = required_env("CLUSTER_ID")
    hash_salt = required_env("HASH_SALT").encode("utf-8")
    if len(hash_salt) < 16:
        raise RuntimeError("HASH_SALT must contain at least 16 characters")

    interval = positive_int("INTERVAL_SECONDS", 60, 3600)
    max_pods = positive_int("MAX_PODS", 150, 500)
    max_events = positive_int("MAX_EVENTS", 60, 200)
    verify_tls = os.getenv("VERIFY_TLS", "true").lower() == "true"
    preserve_namespaces = env_bool("PRESERVE_NAMESPACES", True)
    event_message_mode = env_choice("EVENT_MESSAGE_MODE", "scrubbed", {"scrubbed", "summary", "none"})
    logs_enabled = env_bool("LOGS_ENABLED", False)
    command_poll_seconds = positive_int("COMMAND_POLL_SECONDS", 5, 300)
    log_max_lines = positive_int("LOGS_MAX_LINES", 500, 5000)
    log_max_lookback_minutes = positive_int("LOGS_MAX_LOOKBACK_MINUTES", 60, 1440)
    log_include_previous = env_bool("LOGS_INCLUDE_PREVIOUS", True)
    log_mask_emails = env_bool("LOGS_MASK_EMAILS", True)
    log_mask_public_ips = env_bool("LOGS_MASK_PUBLIC_IPS", True)
    log_mask_internal_ips = env_bool("LOGS_MASK_INTERNAL_IPS", False)
    log_storage_mode = env_choice("LOG_STORAGE_MODE", "none", {"none", "sanitized_evidence", "customer_storage"})
    external_log_source = env_choice("EXTERNAL_LOG_SOURCE", "none", {"none", "kubernetes", "loki", "opensearch", "splunk", "datadog"})
    external_log_source_url = os.getenv("EXTERNAL_LOG_SOURCE_URL", "").strip()
    external_log_source_tenant_id = os.getenv("EXTERNAL_LOG_SOURCE_TENANT_ID", "").strip()
    external_log_source_timeout_seconds = positive_int("EXTERNAL_LOG_SOURCE_TIMEOUT_SECONDS", 10, 60)
    manifests_enabled = env_bool("MANIFESTS_ENABLED", True)
    max_manifests = positive_int("MAX_MANIFESTS", 80, 300)
    manifest_max_yaml_chars = positive_int("MANIFEST_MAX_YAML_CHARS", 12000, 50000)
    manifest_secret_metadata = env_bool("MANIFEST_SECRET_METADATA", True)
    manifest_configmap_values = env_bool("MANIFEST_CONFIGMAP_VALUES", False)
    # Object names ship in the clear so an engineer can act on them directly. REDACT_OBJECT_NAMES
    # lets a customer opt out and receive aliases instead.
    manifest_real_names = not env_bool("REDACT_OBJECT_NAMES", False)
    endpoint = f"{platform_url}/api/agent/ingest"
    config_source = load_kubernetes_config()
    collector = ClusterCollector(
        hash_salt,
        max_pods=max_pods,
        max_events=max_events,
        preserve_namespaces=preserve_namespaces,
        event_message_mode=event_message_mode,
        logs_enabled=logs_enabled,
        log_max_lines=log_max_lines,
        log_max_lookback_minutes=log_max_lookback_minutes,
        log_include_previous=log_include_previous,
        log_mask_emails=log_mask_emails,
        log_mask_public_ips=log_mask_public_ips,
        log_mask_internal_ips=log_mask_internal_ips,
        log_storage_mode=log_storage_mode,
        external_log_source=external_log_source,
        external_log_source_url=external_log_source_url,
        external_log_source_tenant_id=external_log_source_tenant_id,
        external_log_source_timeout_seconds=external_log_source_timeout_seconds,
        manifests_enabled=manifests_enabled,
        max_manifests=max_manifests,
        manifest_max_yaml_chars=manifest_max_yaml_chars,
        manifest_secret_metadata=manifest_secret_metadata,
        manifest_configmap_values=manifest_configmap_values,
        manifest_real_names=manifest_real_names,
    )
    session = requests.Session()
    identity_source, identity_scheme = stable_cluster_identity_source(collector, cluster_name)
    cluster_id = stable_cluster_identifier(identity_source, identity_scheme)
    workload_id = collector.alias("snapshot", cluster_id)
    failures = 0

    logger.info(
        "Agent %s started; kubernetes_config=%s interval=%ss command_poll=%ss max_pods=%s max_events=%s preserve_namespaces=%s event_message_mode=%s logs_enabled=%s log_storage_mode=%s external_log_source=%s manifests_enabled=%s max_manifests=%s",
        AGENT_VERSION,
        config_source,
        interval,
        command_poll_seconds,
        max_pods,
        max_events,
        preserve_namespaces,
        event_message_mode,
        logs_enabled,
        log_storage_mode,
        external_log_source,
        manifests_enabled,
        max_manifests,
    )

    while not stop_event.is_set():
        cycle_started = time.monotonic()
        try:
            signals, redactions = collector.collect()
            signals["cluster_identity"] = {
                "scheme": identity_scheme,
                "alias": cluster_name,
            }
            payload = {
                "cluster_id": cluster_id,
                "workload_id": workload_id,
                "signals": signals,
                "redactions": redactions,
                "sent_at": datetime.now(timezone.utc).isoformat(),
            }
            encoded_size = len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
            if encoded_size > 900_000:
                raise RuntimeError(f"Agent payload is too large ({encoded_size} bytes); reduce MAX_PODS or MAX_EVENTS")
            result = deliver(session, endpoint, agent_key, payload, verify_tls)
            if logs_enabled:
                handle_commands(session, platform_url, agent_key, collector, verify_tls)
            failures = 0
            logger.info(
                "Snapshot accepted id=%s pods=%s warnings=%s bytes=%s redactions=%s",
                result.get("snapshot_id"),
                signals["summary"]["pods_observed"],
                signals["summary"]["warning_events_observed"],
                encoded_size,
                redactions + int(result.get("server_redactions", 0)),
            )
        except requests.HTTPError as exc:
            failures += 1
            status = exc.response.status_code if exc.response is not None else "unknown"
            logger.error("Snapshot rejected by platform; status=%s", status)
            if status in {401, 403}:
                logger.error("Agent credentials were rejected; verify AGENT_KEY")
        except Exception as exc:
            failures += 1
            logger.warning("Collection or delivery failed: %s", exc)

        elapsed = time.monotonic() - cycle_started
        backoff = min(300, interval * (2 ** min(failures, 4))) if failures else interval
        wait_seconds = max(1, backoff - elapsed) + random.uniform(0, min(5, backoff * 0.1))
        remaining = wait_seconds
        while remaining > 0 and not stop_event.is_set():
            chunk = min(command_poll_seconds if logs_enabled else remaining, remaining)
            if stop_event.wait(chunk):
                break
            remaining -= chunk
            if logs_enabled and remaining > 0:
                try:
                    handle_commands(session, platform_url, agent_key, collector, verify_tls)
                except requests.HTTPError as exc:
                    status = exc.response.status_code if exc.response is not None else "unknown"
                    logger.warning("Command poll rejected by platform; status=%s", status)
                except Exception as exc:
                    logger.warning("Command poll failed: %s", exc)

    session.close()
    logger.info("Agent stopped")


if __name__ == "__main__":
    install_signal_handlers()
    try:
        run()
    except Exception as exc:
        logger.error("Agent startup failed: %s", exc)
        sys.exit(1)
