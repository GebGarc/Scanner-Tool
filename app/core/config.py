"""Application configuration"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application
    app_name: str = "Recon App"
    app_version: str = "0.1.0"
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000
    
    # Database
    database_url: str = "sqlite:///./gabeapp.db"
    
    # Optional APIs
    hunter_io_api_key: str = ""
    
    # Security
    secret_key: str = "change-this-in-production"
    
    # File Storage
    upload_dir: Path = Path("./data/uploads")
    evidence_dir: Path = Path("./data/evidence")
    export_dir: Path = Path("./data/exports")
    
    def ensure_directories(self):
        """Create required directories if they don't exist"""
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
