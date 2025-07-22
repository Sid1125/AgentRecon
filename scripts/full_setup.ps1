# scripts/full_setup.ps1

# Auto-elevate to Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "🔐 Relaunching with Administrator privileges..."
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "`n===== 🛠️ AgentRecon Full Setup (Windows, Docker-First) =====`n"

# Utility: Download file
function Download-File($url, $output) {
    Write-Host "⬇️ Downloading from $url..."
    Invoke-WebRequest -Uri $url -OutFile $output
}

# ----------------------------
# Check and Install Python
# ----------------------------
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python is not installed. Downloading and installing Python 3.12..."

    $pyInstaller = "$env:TEMP\python-installer.exe"
    Download-File "https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe" $pyInstaller

    Start-Process -FilePath $pyInstaller -ArgumentList `
        "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_doc=0" -Wait

    # Reload path
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Python install failed. Please install manually from https://www.python.org"
        exit 1
    } else {
        Write-Host "✅ Python installed successfully."
    }
} else {
    Write-Host "✅ Python is already installed."
}

# ----------------------------
# Check for pip
# ----------------------------
$pipCheck = python -m pip --version 2>$null
if (-not $pipCheck) {
    Write-Host "⚠️ pip not found. Installing pip via ensurepip..."
    python -m ensurepip --upgrade
} else {
    Write-Host "✅ pip is available."
}

# ----------------------------
# Setup Virtual Environment
# ----------------------------
$venvPath = Join-Path -Path $PSScriptRoot -ChildPath "..\venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "`n🔧 Creating virtual environment in venv ..."
    python -m venv $venvPath
} else {
    Write-Host "✅ Virtual environment already exists."
}

# Activate virtual environment
$activateScript = Join-Path -Path $venvPath -ChildPath "Scripts\Activate.ps1"
Write-Host "⚙️ Activating virtual environment..."
& $activateScript

# ----------------------------
# Install Python Requirements
# ----------------------------
$requirementsFile = Join-Path -Path $PSScriptRoot -ChildPath "..\requirements.txt"
if (Test-Path $requirementsFile) {
    Write-Host "📦 Installing Python dependencies from requirements.txt..."
    & "$venvPath\Scripts\python.exe" -m pip install --upgrade pip
    & "$venvPath\Scripts\python.exe" -m pip install -r $requirementsFile
} else {
    Write-Host "⚠️ requirements.txt not found, skipping Python dependency installation."
}

# ----------------------------
# Check and Install Docker
# ----------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker not found. Downloading Docker Desktop..."

    $dockerInstaller = "$env:TEMP\DockerDesktopInstaller.exe"
    Download-File "https://desktop.docker.com/win/stable/Docker%20Desktop%20Installer.exe" $dockerInstaller

    Start-Process -FilePath $dockerInstaller -ArgumentList "install", "--quiet" -Wait
    Write-Host "✅ Docker installation initiated. You may need to reboot."
} else {
    Write-Host "✅ Docker is already installed."
}

# ----------------------------
# Check and Install Ollama
# ----------------------------
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Ollama not found. Downloading Ollama..."

    $ollamaInstaller = "$env:TEMP\OllamaSetup.exe"
    Download-File "https://ollama.com/download/OllamaSetup.exe" $ollamaInstaller

    Start-Process -FilePath $ollamaInstaller -ArgumentList "/silent" -Wait
    Write-Host "✅ Ollama installed (you may need to start it manually)."
} else {
    Write-Host "✅ Ollama is already installed."
}

# ----------------------------
# Pull Mistral-Nemo model
# ----------------------------
Write-Host "`n⬇️ Pulling mistral-nemo:latest model..."
ollama pull mistral-nemo:latest

# ----------------------------
# Pull Docker Images
# ----------------------------
$dockerImages = @(
    "ghcr.io/oj/gobuster:latest",
    "instrumentisto/nmap",
    "adarnimrod/masscan",
    "ghcr.io/sullo/nikto",
    "rustscan/rustscan:latest",
    "ghcr.io/nabla-c0d3/sslyze:latest",
    "ghcr.io/open-webui/open-webui:main"
)

foreach ($img in $dockerImages) {
    Write-Host "`n🐳 Pulling Docker image: $img ..."
    docker pull $img
}

# ----------------------------
# Start OpenWebUI
# ----------------------------
Write-Host "`n🚀 Starting OpenWebUI in Docker..."
docker run -d -p 3000:8080 `
    --add-host=host.docker.internal:host-gateway `
    -e OLLAMA_BASE_URL=http://host.docker.internal:11434 `
    -v open-webui:/app/backend/data `
    --name open-webui `
    --restart always `
    --health-cmd="exit 0" `
    ghcr.io/open-webui/open-webui:main

# ----------------------------
# Final Instructions
# ----------------------------
Write-Host "`n🎉 All dependencies are set up!"
Write-Host "`n🚦 Next steps:"
Write-Host "1. Ensure Docker and Ollama are running."
Write-Host "2. Run start.bat to start the AgentRecon API + MCP Server."
Write-Host "3. Open http://localhost:3000 for OpenWebUI"
Write-Host "4. Add a connection: host.docker.internal:5001/v1"
Write-Host "5. Use any API key – it's placeholder-only."
Write-Host "`n🧑‍💻 AgentRecon is ready!"
