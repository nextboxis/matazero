# =============================================================================
# matazero — Automated Windows PowerShell Installer
# =============================================================================

Write-Host ""
Write-Host "  __  __       _                            " -ForegroundColor Cyan
Write-Host " |  \/  |     | |                           " -ForegroundColor Cyan
Write-Host " | \  / | __ _| |_ __ _ _______ _ __ ___   " -ForegroundColor Cyan
Write-Host " | |\/| |/ _` | __/ _` |_  / _ \ '__/ _ \  " -ForegroundColor Cyan
Write-Host " | |  | | (_| | || (_| |/ /  __/ | | (_) | " -ForegroundColor Cyan
Write-Host " |_|  |_|\__,_|\__\__,_/___\___|_|  \___/  " -ForegroundColor Cyan
Write-Host "       Forensic Image Intelligence Toolkit   " -ForegroundColor White
Write-Host ""

Write-Host "[*] Checking Python environment..." -ForegroundColor Cyan

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $pythonCmd) {
    Write-Host "[X] Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/ (make sure to check 'Add python.exe to PATH')." -ForegroundColor Yellow
    exit 1
}

$pyVer = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "[OK] Found Python $pyVer" -ForegroundColor Green

$installDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $installDir) {
    $installDir = Get-Location
}
Set-Location $installDir

Write-Host "[*] Upgrading pip and build tools..." -ForegroundColor Cyan
& python -m pip install --upgrade pip setuptools wheel --quiet

Write-Host "[*] Installing matazero package..." -ForegroundColor Cyan
& python -m pip install -e .

Write-Host ""
Write-Host "[*] Checking for Ollama local AI vision..." -ForegroundColor Cyan
$ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
if ($ollamaCmd) {
    Write-Host "[OK] Ollama is installed on this system." -ForegroundColor Green
} else {
    Write-Host "[i] Ollama is not installed. To enable offline vision AI (matazero ask), download Ollama from: https://ollama.com/download/windows" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[*] Verifying installation..." -ForegroundColor Cyan
& python -m matazero --version

Write-Host ""
Write-Host "[✔] matazero installation completed successfully!" -ForegroundColor Green
Write-Host "You can now run:" -ForegroundColor White
Write-Host "  matazero --help" -ForegroundColor Cyan
Write-Host "  mata diff image1.jpg image2.jpg" -ForegroundColor Cyan
Write-Host "  python -m matazero analyze photo.jpg -a" -ForegroundColor Cyan
Write-Host ""
