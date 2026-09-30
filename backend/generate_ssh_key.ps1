# =============================================================
# generate_ssh_key.ps1  -  IDS_Snort_Project V2 Setup (Step 1)
# Run this on the IDS (monitoring) machine ONLY.
# =============================================================
# Generates a dedicated Ed25519 SSH key pair for V2 remote
# Victim PC firewall enforcement.
# =============================================================

$keyPath = "$env:USERPROFILE\.ssh\ids_victim_key"
$pubPath = "$keyPath.pub"

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  IDS V2 - SSH Key Generator" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# -- Ensure .ssh folder exists ---------------------------------
$sshDir = "$env:USERPROFILE\.ssh"
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir | Out-Null
    Write-Host "[OK] Created $sshDir" -ForegroundColor Green
}

# -- Generate key (skip if already exists) --------------------
if (Test-Path $keyPath) {
    Write-Host "[INFO] Key already exists at: $keyPath" -ForegroundColor Yellow
    Write-Host "       Delete it first if you want to regenerate." -ForegroundColor Yellow
} else {
    Write-Host "[...] Generating Ed25519 SSH key pair..." -ForegroundColor White
    & ssh-keygen -t ed25519 -f "$keyPath" -N '""' -C "IDS_V2_victim_access"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] ssh-keygen failed." -ForegroundColor Red
        Write-Host "        Install OpenSSH client:" -ForegroundColor Yellow
        Write-Host "        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "[OK] Key pair created." -ForegroundColor Green
}

# -- Print the public key --------------------------------------
$pubKey = Get-Content $pubPath -Raw
Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
Write-Host "  PUBLIC KEY (copy this to the Victim PC):" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host $pubKey.Trim() -ForegroundColor Yellow
Write-Host ""

# -- Print .env values -----------------------------------------
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Add these values to backend\.env:" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "VICTIM_PC_IP=<enter Victim PC LAN IP here>" -ForegroundColor White
Write-Host "VICTIM_PC_USER=Administrator" -ForegroundColor White
Write-Host "VICTIM_SSH_KEY=$keyPath" -ForegroundColor White
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  NEXT STEP: On the Victim PC (as Administrator):" -ForegroundColor Cyan
Write-Host "    powershell -ExecutionPolicy Bypass -File backend\setup_v2_victim.ps1" -ForegroundColor Yellow
Write-Host "  and paste the PUBLIC KEY above when prompted." -ForegroundColor White
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""
