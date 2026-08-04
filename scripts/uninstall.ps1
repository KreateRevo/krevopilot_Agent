param(
  [string]$Namespace = "krevopilot-system",
  [string]$ManifestUrl = "https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/kubernetes.yaml"
)

$ErrorActionPreference = "Stop"

kubectl delete -f $ManifestUrl --ignore-not-found=true
kubectl delete secret krevopilot-agent --namespace $Namespace --ignore-not-found=true
kubectl delete namespace $Namespace --ignore-not-found=true
