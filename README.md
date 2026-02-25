# Recon App

A **local-first, import-driven** security assessment workspace built with FastAPI, HTMX, and SQLite. Designed for authorized security practitioners to organize, normalize, search, and report on pentesting artifacts.

## ⚠️ Legal & Safety Notice

**THIS TOOL IS FOR AUTHORIZED SECURITY ASSESSMENTS ONLY.**

- ✅ Use only on systems you own or have explicit written authorization to test
- ✅ Upload and reference ROE (Rules of Engagement) documentation for each engagement
- ✅ Maintain strict scope boundaries using the allowlist feature
- ❌ Never use for unauthorized access, exploitation, or malicious purposes
- ❌ Never scan targets outside your defined scope

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Poetry** (recommended) or pip
- **Docker Desktop** (optional, for Nmap helper utility)

### Installation

1. **Clone or navigate to the project:**
   ```powershell
   cd ReconApp
   ```

2. **Install dependencies using Poetry:**
   ```powershell
   poetry install
   ```

   Or using pip:
   ```powershell
   pip install -r requirements.txt
   ```

3. **Copy environment file:**
   ```powershell
   copy .env.example .env
   ```

4. **Run the application:**
   ```powershell
   poetry run python app/main.py
   ```

   Or:
   ```powershell
   poetry run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

5. **Access the web interface:**
   ```
   http://localhost:8000
   ```

## 📋 Features

### Core Capabilities

- **Command Center**: Centralized dashboard for network scanning and security audits.
- **SSL Analysis**: Deep dive into certificate chains and expiry.
- **Security Headers**: Audit HSTS, CSP, and X-Frame-Options.
- **Subdomain Recon**: Enumerate public subdomains via transparency logs.
- **Email Security**: Validate SPF and DMARC policies.

### Nmap Scanner Utility

- **Quick Scan**: Fastest discovery of active hosts.
- **Intense Scan**: Service versioning and script analysis.
- **Stealth Scan**: Quiet discovery for stealthier engagements.

## 📁 Project Structure

```
ReconApp/
├── app/
│   ├── core/           # Config, settings
│   ├── db/             # SQLAlchemy models, session
│   ├── routers/        # FastAPI routes (Nmap, Security)
│   ├── services/       # Business logic (Security Analysis)
│   ├── static/         # CSS, JS
│   ├── templates/      # Jinja2 HTML templates
│   └── main.py         # FastAPI app entry point
├── tools/
│   └── nmap_docker/    # Docker helper for Nmap
├── tests/              # Unit tests
├── examples/           # Sample artifacts
├── pyproject.toml      # Project dependencies
└── README.md
```

## 🔐 Security Best Practices

1. **Scope Boundaries**: Review out-of-scope flags in imported data.
2. **Access Control**: Run on `127.0.0.1` only by default.
3. **Authorized Use**: Only scan targets within your engagement scope.

## 🎨 UI Features

- **Dark/Light Mode**: Toggle in sidebar, preference saved to localStorage.
- **HTMX Partials**: Fast, dynamic UI updates without full page reloads.
- **Responsive Design**: Works on desktop and tablet screens.

## 📄 License

This project is for educational and authorized security assessment purposes only. Use responsibly.
