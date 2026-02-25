# Nmap Docker Helper for Windows 11
# Run Nmap scans in Docker and output XML for import into GabeApp

param(
    [Parameter(Mandatory=$true)]
    [string]$targets,
    
    [Parameter(Mandatory=$false)]
    [string]$output = "scan.xml",
    
    [Parameter(Mandatory=$false)]
    [string]$options = "-sV -sC"
)

Write-Host "🔍 GabeApp Nmap Docker Helper" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Create output directory
$outputDir = Join-Path $PWD "output"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$outputPath = Join-Path $outputDir $output

Write-Host "🎯 Targets: $targets" -ForegroundColor Yellow
Write-Host "📝 Output: $outputPath" -ForegroundColor Yellow
Write-Host "⚙️  Options: $options" -ForegroundColor Yellow
Write-Host ""

Write-Host "⚠️  IMPORTANT: Only scan targets within your authorized scope!" -ForegroundColor Red
Write-Host ""

# Build command
$dockerArgs = @(
    "run",
    "--rm",
    "-v", "${outputDir}:/scans",
    "gabeapp-nmap"
)

# Add Nmap options and targets
$nmapArgs = $options.Split(" ") + @("-oX", "/scans/$output", $targets)
$fullArgs = $dockerArgs + $nmapArgs

Write-Host "🚀 Running scan..." -ForegroundColor Cyan
Write-Host "Command: docker $($fullArgs -join ' ')" -ForegroundColor DarkGray
Write-Host ""

# Run Docker
& docker @fullArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Scan complete!" -ForegroundColor Green
    Write-Host "📁 Output saved to: $outputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Open GabeApp in your browser" -ForegroundColor White
    Write-Host "2. Navigate to your engagement" -ForegroundColor White
    Write-Host "3. Use 'Import Nmap XML' and upload $output" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "❌ Scan failed. Check the output above." -ForegroundColor Red
    exit 1
}
