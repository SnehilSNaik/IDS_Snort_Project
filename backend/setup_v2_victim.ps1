# =============================================================
# setup_v2_victim.ps1  —  IDS_Snort_Project V2 Setup (Step 2)
# Run this on the VICTIM PC as Administrator.
# =============================================================
# 1. Installs & starts the OpenSSH Server Windows feature
# 2. Adds the IDS machine's public key to authorized_keys
# 3. Sets firewall rule to allow inbound SSH (port 22)
# =============================================================

#Requires -RunAsAdministrator

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  IDS V2 — Victim PC SSH Setup" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Install OpenSSH Server feature ────────────────────
Write-Host "[1/4] Checking OpenSSH Server installation..." -ForegroundColor White
$sshFeature = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"
if ($sshFeature.State -ne "Installed") {
    Write-Host "      Installing OpenSSH Server..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Could not install OpenSSH Server. Check internet connection." -ForegroundColor Red
        exit 1
    }
    Write-Host "      [OK] OpenSSH Server installed." -ForegroundColor Green
} else {
    Write-Host "      [OK] OpenSSH Server already installed." -ForegroundColor Green
}

# ── Step 2: Start & auto-start SSH service ────────────────────
Write-Host "[2/4] Starting and enabling sshd service..." -ForegroundColor White
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Write-Host "      [OK] sshd is running and set to auto-start." -ForegroundColor Green

# ── Step 3: Windows Firewall — allow SSH inbound ─────────────
Write-Host "[3/4] Ensuring firewall allows inbound SSH (port 22)..." -ForegroundColor White
$rule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
        -DisplayName "OpenSSH Server (sshd)" `
        -Enabled True -Direction Inbound `
        -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    Write-Host "      [OK] Firewall rule created for port 22." -ForegroundColor Green
} else {
    Write-Host "      [OK] Firewall rule already exists." -ForegroundColor Green
}

# ── Step 4: Add IDS machine's public key ─────────────────────
Write-Host "[4/4] Adding IDS machine's public SSH key..." -ForegroundColor White
Write-Host ""
Write-Host "  Paste the PUBLIC KEY from the IDS machine" -ForegroundColor Yellow
Write-Host "  (output of generate_ssh_key.ps1), then press Enter:" -ForegroundColor Yellow
Write-Host ""
$pubKey = Read-Host "  Public key"

if ([string]::IsNullOrWhiteSpace($pubKey)) {
    Write-Host "  [SKIP] No key entered. You can add it manually later." -ForegroundColor Yellow
    Write-Host "         File: C:\ProgramData\ssh\administrators_authorized_keys" -ForegroundColor White
} else {
    # Administrators use a special global authorized_keys file
    $authKeysDir  = "C:\ProgramData\ssh"
    $authKeysFile = "$authKeysDir\administrators_authorized_keys"
    if (-not (Test-Path $authKeysDir)) { New-Item -ItemType Directory -Path $authKeysDir | Out-Null }

    # Append only if the key isn't already there
    $existing = if (Test-Path $authKeysFile) { Get-Content $authKeysFile -Raw } else { "" }
    if ($existing -notlike "*$($pubKey.Trim())*") {
        Add-Content -Path $authKeysFile -Value $pubKey.Trim()
        Write-Host "      [OK] Public key added to $authKeysFile" -ForegroundColor Green
    } else {
        Write-Host "      [OK] Public key already present." -ForegroundColor Green
    }

    # Fix permissions — sshd requires strict ACL on this file
    icacls $authKeysFile /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
    Write-Host "      [OK] Permissions set on authorized_keys." -ForegroundColor Green
}

# ── Done ──────────────────────────────────────────────────────
$victimIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
Write-Host "  Victim PC setup COMPLETE!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  This machine's LAN IP : $victimIP" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Now on the IDS machine, update backend\.env:" -ForegroundColor White
Write-Host "    VICTIM_PC_IP=$victimIP" -ForegroundColor Cyan
Write-Host "    VICTIM_PC_USER=Administrator" -ForegroundColor Cyan
Write-Host "    VICTIM_SSH_KEY=C:\Users\<you>\.ssh\ids_victim_key" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Then restart the backend — V2 is live!" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""
