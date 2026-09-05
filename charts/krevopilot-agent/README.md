# KrevoPilot Agent Helm Chart

Install the KrevoPilot Agent into a Kubernetes cluster.

## Install

```bash
helm install krevopilot-agent ./charts/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="https://pilot.yourcompany.com" \
  --set cluster.id="customer-prod-cluster" \
  --set agent.key="paste-agent-key-from-kreaterevopilot"
```

## Install from a published chart repo

After KreateRevo publishes the chart:

```bash
helm repo add kreate-revo https://kreaterevo.github.io/Krevopilot-agent-helm-charts
helm repo update

helm install krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="https://pilot.yourcompany.com" \
  --set cluster.id="customer-prod-cluster" \
  --set agent.key="paste-agent-key-from-kreaterevopilot"
```

If `helm repo add` returns `404 Not Found`, the public Helm repository is not enabled yet. For internal/local testing from this repository, use:

```bash
helm upgrade --install krevopilot-agent ./charts/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="http://host.docker.internal:8000" \
  --set cluster.id="local-test" \
  --set agent.key="paste-agent-key-from-kreaterevopilot" \
  --set agent.allowInsecureHttp=true
```

## Recommended production install with a values file

Create `values.yaml`:

```yaml
platform:
  url: https://pilot.yourcompany.com

cluster:
  id: customer-prod-cluster

agent:
  key: paste-agent-key-from-kreaterevopilot
  preserveNamespaces: true
  eventMessageMode: scrubbed

image:
  repository: mani7022/krevopilot-agent
  tag: "2.0.9"
  # Optional for enterprise change control:
  # digest: "sha256:REPLACE_WITH_PUBLISHED_DIGEST"
```

Install:

```bash
helm install krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  -f values.yaml
```

## Stricter privacy / enterprise install

Use this when namespace names or event message text are considered sensitive:

```yaml
agent:
  key: paste-agent-key-from-kreaterevopilot
  preserveNamespaces: false
  eventMessageMode: summary # scrubbed | summary | none

networkPolicy:
  enabled: true
  allowDns: true
  egressCidrs:
    - "203.0.113.10/32" # replace with your Pilot ingress/load-balancer IP
```

Notes:

- The agent does not read Secrets, ConfigMaps, application logs, or environment variable values in regular snapshots.
- On-demand pod log permission is disabled by default. Enable `logs.enabled=true` only when the customer wants live log viewing/investigation.
- Kubernetes NetworkPolicy cannot restrict by URL; use the Pilot endpoint IP/CIDR.
- Agent install keys are one-time visible in Pilot. Generate a new key if the original key is lost.

## Optional on-demand logs

Kubernetes pod logs come from the Kubernetes API, not from a customer database.
The agent should not create or manage a database for logs.

```yaml
logs:
  enabled: true
  maxLines: 500
  maxLookbackMinutes: 60
  includePrevious: true
  storageMode: none # none | sanitized_evidence | customer_storage
  redact:
    maskEmails: true
    maskPublicIPs: true
    maskInternalIPs: false
```

For strict companies, keep `logs.enabled=false` and ask users to paste selected
logs manually into Krevo AI. For companies with existing historical logs, connect
their own Loki service. Loki must be fed by Promtail or Grafana Alloy; Loki
alone does not collect container logs.

```yaml
externalLogSource:
  type: loki # none | kubernetes | loki | opensearch | splunk | datadog
  url: http://loki-gateway.observability.svc.cluster.local
  tenantId: ""
  timeoutSeconds: 10
```

## Use an existing Secret

Create a Secret with keys `agent-key` and `hash-salt`, then install with:

```bash
helm install krevopilot-agent ./charts/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="https://pilot.yourcompany.com" \
  --set cluster.id="customer-prod-cluster" \
  --set agent.existingSecret="krevopilot-agent"
```

## Verify

```bash
kubectl get pods -n krevopilot-system
kubectl logs deployment/krevopilot-agent -n krevopilot-system --tail=50
```

Expected log:

```text
Snapshot accepted id=...
```

## Uninstall

```bash
helm uninstall krevopilot-agent -n krevopilot-system
```
