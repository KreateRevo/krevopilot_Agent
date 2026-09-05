# KrevoPilot Agent

Standalone Kubernetes agent for KrevoPilot.

Install this agent inside a customer Kubernetes cluster to send privacy-safe workload health, warning events, node signals, and optional Metrics Server usage back to KrevoPilot.

The agent is separate from the KrevoPilot app:

- KrevoPilot runs as your platform.
- KrevoPilot Agent runs inside each customer cluster.
- The agent sends outbound HTTPS reports to KrevoPilot.
- KrevoPilot uses those reports for Applications, Cost Optimization, and AI Assistant evidence.

## What the agent collects

- Pod phase, readiness, restart counts, and container waiting/terminated reasons
- Kubernetes warning events
- Node readiness and pressure signals
- CPU and memory usage when Metrics Server is installed
- Resource requests and limits

## What the agent does not collect

- Kubernetes Secrets
- Raw application logs in regular snapshots
- Environment variable values
- Full pod, node, container, or workload names

## On-demand logs

KrevoPilot is designed to fetch logs only when a user explicitly asks for a
specific pod/container/time window. Regular agent snapshots do not include logs.

For MVP security, keep full log storage out of the agent:

- The agent fetches live pod logs from the Kubernetes API.
- The agent redacts secrets/tokens locally before anything leaves the cluster.
- KrevoPilot should save only short sanitized evidence snippets for an investigation.
- Raw log history should stay in customer-owned systems such as Loki, OpenSearch, Splunk, Datadog, or object storage.

Enable on-demand log permission only if the customer accepts it:

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

If the customer already has Loki, or installs Loki inside the customer cluster,
the agent can query that customer-owned log store on demand. Loki must receive
pod logs from a shipper such as Promtail or Grafana Alloy; Loki by itself does
not read container log files.

```yaml
externalLogSource:
  type: loki # none | kubernetes | loki | opensearch | splunk | datadog
  url: http://loki-gateway.observability.svc.cluster.local
  tenantId: "" # optional; used only when Loki multi-tenancy is enabled
  timeoutSeconds: 10
```

When `externalLogSource.type=loki`, normal live-log requests are read from Loki.
`Previous logs` still use the Kubernetes API because Loki does not expose the
Kubernetes previous-container switch. The agent redacts log content before
sending it to KrevoPilot.

Kubernetes pod logs are not stored by the agent. For historical retention,
customers should store logs in their own Loki/OpenSearch/Splunk/Datadog setup
and let the agent query only the specific pod/container/time window requested by
the user.

Pod, node, container, workload, and object names are converted into stable privacy-safe aliases before leaving the cluster. Namespace names are preserved because they are the main way users understand where workloads live.

For stricter customer environments, set:

```yaml
agent:
  preserveNamespaces: false
  eventMessageMode: summary
```

`eventMessageMode` options:

- `scrubbed` - default; sends redacted event messages for better troubleshooting.
- `summary` - sends only object kind and event reason.
- `none` - sends no event message text.

## Repository contents

| Path | Purpose |
| --- | --- |
| `Dockerfile` | Builds the agent image |
| `charts/krevopilot-agent` | Helm chart for company installs |
| `kubernetes.yaml` | Public Kubernetes install manifest |
| `scripts/install.ps1` | Windows/PowerShell installer |
| `scripts/install.sh` | macOS/Linux installer |
| `scripts/uninstall.ps1` | Windows/PowerShell uninstall helper |
| `scripts/uninstall.sh` | macOS/Linux uninstall helper |
| `examples/secret.example.yaml` | Example Kubernetes Secret |
| `agent.py`, `collector.py`, `privacy.py` | Agent runtime |
| `test_agent.py` | Unit tests |

## For KrevoPilot owners

Before customers install the agent, prepare your KrevoPilot backend.

### 1. Set the ingest key

In your KrevoPilot backend environment, set:

```env
AGENT_INGEST_KEY=replace-with-a-long-random-value
AGENT_REQUIRE_HTTPS=true
```

Restart the backend after changing these values.

Give the same `AGENT_INGEST_KEY` to the customer as their `AGENT_KEY`.

For local testing only, you can use:

```env
AGENT_REQUIRE_HTTPS=false
```

### 2. Make KrevoPilot reachable

Customers need a URL their cluster can reach, for example:

```text
https://pilot.yourcompany.com
```

The agent sends reports to:

```text
https://pilot.yourcompany.com/api/agent/ingest
```

### 3. Publish the agent image

Build and push the image:

```powershell
docker build -t mani7022/krevopilot-agent:2.0.9 .
docker push mani7022/krevopilot-agent:2.0.9
```

If your image registry is different, update the install examples below.

### 4. Publish the Helm chart

For a Datadog-style install experience, publish `charts/krevopilot-agent` through a Helm chart repository.

Simple options:

- GitHub Pages with chart packages
- ChartMuseum
- OCI registry
- Artifact Hub listing after the chart repo is public

This repo includes `.github/workflows/chart-release.yml`, which packages the chart and pushes the Helm repository files to the `gh-pages` branch.

After the first successful workflow run, enable GitHub Pages once:

1. Open GitHub repository Settings.
2. Go to Pages.
3. Select `Deploy from a branch`.
4. Select branch `gh-pages` and folder `/`.

Then the Helm repo URL is:

```text
https://kreaterevo.github.io/krevopilot-agent
```

Verify it before giving the command to customers:

```bash
helm repo add kreate-revo https://kreaterevo.github.io/Krevopilot-agent-helm-charts
helm repo update
helm search repo kreate-revo/krevopilot-agent
```

If this returns `404 Not Found`, the chart package may exist in the `gh-pages` branch but GitHub Pages is not publicly serving it yet. Check:

- Repository Settings → Pages is enabled.
- Source is `Deploy from a branch`.
- Branch is `gh-pages`, folder `/`.
- The repository is public, or your beta customer has an authenticated/private chart install path.

For local chart package testing:

```bash
helm package charts/krevopilot-agent
helm install krevopilot-agent ./krevopilot-agent-0.1.0.tgz \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="https://pilot.yourcompany.com" \
  --set cluster.id="customer-prod-cluster" \
  --set agent.key="paste-agent-key-from-krevopilot"
```

For local development without the public Helm repo:

```bash
helm upgrade --install krevopilot-agent ./charts/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="http://host.docker.internal:8000" \
  --set cluster.id="local-test" \
  --set agent.key="paste-agent-key-from-krevopilot" \
  --set agent.allowInsecureHttp=true \
  --set image.repository="mani7022/krevopilot-agent" \
  --set image.tag="2.0.25"
```

## Recommended customer install: Helm

This is the preferred installation method for companies.

```bash
helm repo add kreate-revo https://kreaterevo.github.io/Krevopilot-agent-helm-charts
helm repo update

helm install krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="https://pilot.yourcompany.com" \
  --set cluster.id="customer-prod-cluster" \
  --set agent.key="paste-agent-key-from-krevopilot"
```

If your image is hosted somewhere else:

```bash
helm install krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  --set platform.url="https://pilot.yourcompany.com" \
  --set cluster.id="customer-prod-cluster" \
  --set agent.key="paste-agent-key-from-krevopilot" \
  --set image.repository="mani7022/krevopilot-agent" \
  --set image.tag="2.0.25"
```

## Recommended production install with values file

Create `values.yaml`:

```yaml
platform:
  url: https://pilot.yourcompany.com

cluster:
  id: customer-prod-cluster

agent:
  key: paste-agent-key-from-krevopilot

image:
  repository: mani7022/krevopilot-agent
  tag: "2.0.9"
```

Install:

```bash
helm install krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  -f values.yaml
```

## Alternative install: PowerShell script

Use this when the customer does not use Helm.

```powershell
.\scripts\install.ps1 `
  -PlatformUrl "https://pilot.yourcompany.com" `
  -ClusterId "customer-prod-cluster" `
  -AgentKey "paste-agent-key-from-krevopilot" `
  -Image "mani7022/krevopilot-agent:2.0.25"
```

## Alternative install: macOS/Linux script

```bash
export PLATFORM_URL="https://pilot.yourcompany.com"
export CLUSTER_ID="customer-prod-cluster"
export AGENT_KEY="paste-agent-key-from-krevopilot"
export IMAGE="mani7022/krevopilot-agent:2.0.25"

sh ./scripts/install.sh
```

## Alternative install directly from GitHub raw manifest

After you upload this repo to GitHub, customers can install using the raw manifest URL. Helm is still recommended for most companies.

PowerShell:

```powershell
.\scripts\install.ps1 `
  -PlatformUrl "https://pilot.yourcompany.com" `
  -ClusterId "customer-prod-cluster" `
  -AgentKey "paste-agent-key-from-krevopilot" `
  -Image "mani7022/krevopilot-agent:2.0.25" `
  -ManifestUrl "https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/kubernetes.yaml"
```

macOS/Linux:

```bash
export PLATFORM_URL="https://pilot.yourcompany.com"
export CLUSTER_ID="customer-prod-cluster"
export AGENT_KEY="paste-agent-key-from-krevopilot"
export IMAGE="mani7022/krevopilot-agent:2.0.25"
export MANIFEST_URL="https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/kubernetes.yaml"

curl -fsSL https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/scripts/install.sh | sh
```

The public source repository is `KreateRevo/krevopilot_Agent`.

## Connect with KrevoPilot

Use this checklist when onboarding a company:

1. In KrevoPilot, generate or choose an `AGENT_INGEST_KEY`.
2. Set that key on the KrevoPilot backend as `AGENT_INGEST_KEY`.
3. Give the company:
   - KrevoPilot URL, for example `https://pilot.yourcompany.com`
   - Agent key
   - Cluster ID they should use, for example `acme-prod-us-east`
   - Helm install command
   - Agent image, for example `mani7022/krevopilot-agent:2.0.25`
4. Company runs the Helm install command in their Kubernetes cluster.
5. In KrevoPilot, open:
   - Overview
   - Applications
   - Cost Optimizer
   - AI Assistant
6. Wait up to one report interval, usually 60 seconds.

If the connection works, the agent logs show:

```text
Snapshot accepted id=...
```

## Verify install

```bash
kubectl get pods -n krevopilot-system
kubectl logs deployment/krevopilot-agent -n krevopilot-system --tail=50
```

Expected result:

```text
Snapshot accepted id=...
```

If Metrics Server is missing, the agent still works. CPU/memory live usage will show unavailable until Metrics Server is installed.

## Local/minikube testing

For local HTTP testing only:

PowerShell:

```powershell
.\scripts\install.ps1 `
  -PlatformUrl "http://host.docker.internal:8000" `
  -ClusterId "local-minikube" `
  -AgentKey "change-agent-key" `
  -Image "mani7022/krevopilot-agent:2.0.25" `
  -AllowInsecureHttp
```

macOS/Linux:

```bash
export PLATFORM_URL="http://host.docker.internal:8000"
export CLUSTER_ID="local-minikube"
export AGENT_KEY="change-agent-key"
export IMAGE="mani7022/krevopilot-agent:2.0.25"
export ALLOW_INSECURE_HTTP=true

sh ./scripts/install.sh
```

Production should use HTTPS.

## Uninstall

Helm:

```bash
helm uninstall krevopilot-agent -n krevopilot-system
```

PowerShell script:

```powershell
.\scripts\uninstall.ps1
```

macOS/Linux:

```bash
sh ./scripts/uninstall.sh
```

## Useful settings

| Setting | Default | Meaning |
| --- | ---: | --- |
| `PLATFORM_URL` | required | KrevoPilot URL |
| `CLUSTER_ID` | required | Friendly customer cluster name |
| `AGENT_KEY` | required | Must match KrevoPilot `AGENT_INGEST_KEY` |
| `HASH_SALT` | generated | Used to create privacy-safe aliases |
| `INTERVAL_SECONDS` | `60` | How often the agent reports |
| `MAX_PODS` | `150` | Maximum pods included per report |
| `MAX_EVENTS` | `60` | Maximum warning events included per report |
| `VERIFY_TLS` | `true` | Verify HTTPS certificate |
| `ALLOW_INSECURE_HTTP` | `false` | Allow HTTP platform URLs for local testing only |
| `LOG_LEVEL` | `INFO` | Agent log level |
| `PRESERVE_NAMESPACES` | `true` | Keep namespace names readable; set `false` to alias namespace names |
| `EVENT_MESSAGE_MODE` | `scrubbed` | `scrubbed`, `summary`, or `none` for warning event message privacy |
| `LOGS_ENABLED` | `false` | Enables future on-demand log requests; snapshots still do not send logs |
| `LOGS_MAX_LINES` | `500` | Maximum lines per log request |
| `LOGS_MAX_LOOKBACK_MINUTES` | `60` | Maximum lookback window for live log requests |
| `LOGS_INCLUDE_PREVIOUS` | `true` | Allow previous container logs for CrashLoopBackOff investigations |
| `LOG_STORAGE_MODE` | `none` | `none`, `sanitized_evidence`, or `customer_storage` |
| `EXTERNAL_LOG_SOURCE` | `none` | Customer-owned source: `none`, `kubernetes`, `loki`, `opensearch`, `splunk`, or `datadog` |
| `EXTERNAL_LOG_SOURCE_URL` | empty | Loki base URL, for example `http://loki-gateway.observability.svc.cluster.local` |
| `EXTERNAL_LOG_SOURCE_TENANT_ID` | empty | Optional Loki tenant header value |
| `EXTERNAL_LOG_SOURCE_TIMEOUT_SECONDS` | `10` | Per-query timeout for external log source requests |

## Permissions

The agent uses read-only Kubernetes permissions for:

- Pods
- Events
- Nodes
- Metrics API pods/nodes
- Pod logs only when `logs.enabled=true`

It does not request permission to read Secrets.

## Enterprise hardening options

For stricter production installs, create a values file:

```yaml
agent:
  preserveNamespaces: false
  eventMessageMode: summary

image:
  repository: mani7022/krevopilot-agent
  tag: "2.0.9"
  digest: "sha256:REPLACE_WITH_PUBLISHED_DIGEST"

networkPolicy:
  enabled: true
  allowDns: true
  egressCidrs:
    - "203.0.113.10/32" # replace with your KrevoPilot ingress/load balancer IP
```

Then install:

```bash
helm upgrade --install krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --create-namespace \
  -f values.yaml
```

Notes:

- Kubernetes NetworkPolicy cannot restrict egress by DNS name. Use the CIDR/IPs for your KrevoPilot ingress or load balancer.
- The agent key is shown once by KrevoPilot. If it is lost, generate a new key and upgrade the agent.

## Build and test

```powershell
docker build -t mani7022/krevopilot-agent:2.0.25 .
docker run --rm --entrypoint python mani7022/krevopilot-agent:2.0.25 -m unittest -v test_agent.py
```

## Upgrade

Push a new image version, then upgrade with Helm:

```bash
helm upgrade krevopilot-agent kreate-revo/krevopilot-agent \
  --namespace krevopilot-system \
  --reuse-values \
  --set image.tag="2.0.25"
```

Script/raw manifest fallback:

```bash
kubectl set image deployment/krevopilot-agent agent=mani7022/krevopilot-agent:2.0.9 -n krevopilot-system
kubectl rollout status deployment/krevopilot-agent -n krevopilot-system
```
