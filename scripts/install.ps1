param(
  [Parameter(Mandatory = $true)]
  [string]$PlatformUrl,

  [Parameter(Mandatory = $true)]
  [string]$ClusterId,

  [Parameter(Mandatory = $true)]
  [string]$AgentKey,

  [string]$HashSalt = "",
  [string]$Image = "mani7022/krevopilot-agent:2.0.33",
  [string]$Namespace = "krevopilot-system",
  [string]$ManifestUrl = "https://raw.githubusercontent.com/KreateRevo/krevopilot-agent/main/kubernetes.yaml",
  [switch]$AllowInsecureHttp
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($HashSalt)) {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
  $HashSalt = [Convert]::ToBase64String($bytes)
}

kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic krevopilot-agent `
  --namespace $Namespace `
  --from-literal=agent-key=$AgentKey `
  --from-literal=hash-salt=$HashSalt `
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f $ManifestUrl

kubectl set image deployment/krevopilot-agent agent=$Image --namespace $Namespace
kubectl set env deployment/krevopilot-agent PLATFORM_URL=$PlatformUrl CLUSTER_ID=$ClusterId ALLOW_INSECURE_HTTP=$($AllowInsecureHttp.IsPresent.ToString().ToLower()) --namespace $Namespace

kubectl rollout status deployment/krevopilot-agent --namespace $Namespace
kubectl logs deployment/krevopilot-agent --namespace $Namespace --tail=50
