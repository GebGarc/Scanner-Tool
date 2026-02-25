# Nmap Docker Helper

This directory contains a Docker-based Nmap scanner helper for Windows 11.

## Why Docker?

GabeApp is an **import-first** tool. In v1, it does not execute scans directly. This helper utility allows you to run Nmap scans in a containerized environment and import the results.

## Setup

1. **Install Docker Desktop for Windows**
   - Download from https://www.docker.com/products/docker-desktop/
   - Ensure WSL2 backend is enabled

2. **Build the Docker image:**
   ```powershell
   docker build -t gabeapp-nmap .
   ```

3. **Run a scan:**
   ```powershell
   .\run_nmap.ps1 -targets "192.168.1.1" -output "scan.xml"
   ```

## Usage Examples

### Basic scan:
```powershell
.\run_nmap.ps1 -targets "192.168.1.0/24"
```

### Custom output filename:
```powershell
.\run_nmap.ps1 -targets "10.0.0.1" -output "custom_scan.xml"
```

### Advanced options:
```powershell
.\run_nmap.ps1 -targets "example.com" -options "-sV -sC -A" -output "full_scan.xml"
```

## Import into GabeApp

1. Navigate to your engagement in GabeApp
2. Click "Import Nmap XML"
3. Upload the generated `scan.xml` from the `output/` directory

## Networking Notes

- **Bridge Mode (Default)**: Works on Windows, but target must be accessible from Docker bridge network
- **Host Mode**: May not work on Docker Desktop for Windows due to platform limitations

## Safety Reminders

- Only scan authorized targets
- Verify targets are within your engagement scope
- Keep scan results secure
- Review and upload ROE documentation in GabeApp
