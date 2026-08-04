#!/usr/bin/env sh
set -eu

NAMESPACE="${NAMESPACE:-krevopilot-system}"
MANIFEST_URL="${MANIFEST_URL:-https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/kubernetes.yaml}"

kubectl delete -f "$MANIFEST_URL" --ignore-not-found=true
kubectl delete secret krevopilot-agent --namespace "$NAMESPACE" --ignore-not-found=true
kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
