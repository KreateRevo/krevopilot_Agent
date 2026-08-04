#!/usr/bin/env sh
set -eu

: "${PLATFORM_URL:?Set PLATFORM_URL, for example https://pilot.yourcompany.com}"
: "${CLUSTER_ID:?Set CLUSTER_ID, for example prod-cluster-1}"
: "${AGENT_KEY:?Set AGENT_KEY from KreateRevoPilot}"

NAMESPACE="${NAMESPACE:-krevopilot-system}"
IMAGE="${IMAGE:-mani7022/krevopilot-agent:2.0.25}"
MANIFEST_URL="${MANIFEST_URL:-https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/kubernetes.yaml}"
ALLOW_INSECURE_HTTP="${ALLOW_INSECURE_HTTP:-false}"

if [ -z "${HASH_SALT:-}" ]; then
  HASH_SALT="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)"
fi

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic krevopilot-agent \
  --namespace "$NAMESPACE" \
  --from-literal=agent-key="$AGENT_KEY" \
  --from-literal=hash-salt="$HASH_SALT" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "$MANIFEST_URL"
kubectl set image deployment/krevopilot-agent agent="$IMAGE" --namespace "$NAMESPACE"
kubectl set env deployment/krevopilot-agent PLATFORM_URL="$PLATFORM_URL" CLUSTER_ID="$CLUSTER_ID" ALLOW_INSECURE_HTTP="$ALLOW_INSECURE_HTTP" --namespace "$NAMESPACE"
kubectl rollout status deployment/krevopilot-agent --namespace "$NAMESPACE"
kubectl logs deployment/krevopilot-agent --namespace "$NAMESPACE" --tail=50
