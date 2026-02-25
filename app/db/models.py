"""Database models for Security Assessment Workspace"""
from datetime import datetime
from typing import Optional, List, Any
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, Float, 
    ForeignKey, JSON, Table, Enum as SQLEnum
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.db.session import Base
import enum


# Association tables for many-to-many relationships
finding_asset_association = Table(
    'finding_asset_association',
    Base.metadata,
    Column('finding_id', Integer, ForeignKey('findings.id')),
    Column('asset_id', Integer, ForeignKey('assets.id'))
)

finding_evidence_association = Table(
    'finding_evidence_association',
    Base.metadata,
    Column('finding_id', Integer, ForeignKey('findings.id')),
    Column('evidence_id', Integer, ForeignKey('evidence.id'))
)


class EngagementStatus(str, enum.Enum):
    """Engagement lifecycle status"""
    PLANNING = "planning"
    ACTIVE = "active"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class FindingSeverity(str, enum.Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    """Finding remediation status"""
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"


class EvidenceType(str, enum.Enum):
    """Evidence file types"""
    SCREENSHOT = "screenshot"
    SCAN_REPORT = "scan_report"
    LOG_FILE = "log_file"
    ROE_DOCUMENT = "roe_document"
    OTHER = "other"


class Engagement(Base):
    """Security assessment engagement"""
    __tablename__ = "engagements"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    client_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    operator_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Dates
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Status
    status: Mapped[EngagementStatus] = mapped_column(SQLEnum(EngagementStatus), default=EngagementStatus.PLANNING)
    
    # Scope allowlist (stored as JSON)
    scope_domains: Mapped[List[str]] = mapped_column(JSON, default=list)  # ["example.com", "*.example.com"]
    scope_ips: Mapped[List[str]] = mapped_column(JSON, default=list)  # ["192.168.1.0/24", "10.0.0.1"]
    scope_urls: Mapped[List[str]] = mapped_column(JSON, default=list)  # ["https://app.example.com"]
    
    # ROE reference
    roe_file_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('evidence.id'), nullable=True)
    
    # Relationships
    assets: Mapped[List["Asset"]] = relationship("Asset", back_populates="engagement", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="engagement", cascade="all, delete-orphan")
    evidence: Mapped[List["Evidence"]] = relationship("Evidence", back_populates="engagement", foreign_keys="Evidence.engagement_id", cascade="all, delete-orphan")
    imports: Mapped[List["ImportLog"]] = relationship("ImportLog", back_populates="engagement", cascade="all, delete-orphan")
    osint_results: Mapped[List["OSINTResult"]] = relationship("OSINTResult", back_populates="engagement", cascade="all, delete-orphan")


class Asset(Base):
    """Discovered host/asset"""
    __tablename__ = "assets"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey('engagements.id'), nullable=False)
    
    # Identification
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)  # IPv4/IPv6
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    
    # Details
    os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Scope check
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    scope_check_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Metadata
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # nmap, nessus, etc.
    
    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="assets")
    services: Mapped[List["Service"]] = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship("Finding", secondary=finding_asset_association, back_populates="assets")


class Service(Base):
    """Network service running on an asset"""
    __tablename__ = "services"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey('assets.id'), nullable=False)
    
    # Service details
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")  # tcp, udp
    state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # open, closed, filtered
    service_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # http, ssh, etc.
    service_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    service_product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    service_extrainfo: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Metadata
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="services")


class Finding(Base):
    """Security finding/vulnerability"""
    __tablename__ = "findings"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey('engagements.id'), nullable=False)
    
    # Core details
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Severity
    severity: Mapped[FindingSeverity] = mapped_column(SQLEnum(FindingSeverity), default=FindingSeverity.INFO, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Status
    status: Mapped[FindingStatus] = mapped_column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, index=True)
    
    # References
    cve_ids: Mapped[List[str]] = mapped_column(JSON, default=list)  # ["CVE-2024-1234"]
    cwe_ids: Mapped[List[str]] = mapped_column(JSON, default=list)  # ["CWE-79"]
    external_references: Mapped[List[str]] = mapped_column(JSON, default=list)  # URLs
    
    # Tags and categorization
    tags: Mapped[List[str]] = mapped_column(JSON, default=list)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Source
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)  # nessus, zap, trufflehog
    plugin_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # For Nessus/OpenVAS
    
    # Evidence context
    affected_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    affected_parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Metadata
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="findings")
    assets: Mapped[List["Asset"]] = relationship("Asset", secondary=finding_asset_association, back_populates="findings")
    evidence: Mapped[List["Evidence"]] = relationship("Evidence", secondary=finding_evidence_association, back_populates="findings")


class Evidence(Base):
    """Evidence files and artifacts"""
    __tablename__ = "evidence"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey('engagements.id'), nullable=False)
    
    # File details
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    file_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mime_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    # Security
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    
    # Classification
    evidence_type: Mapped[EvidenceType] = mapped_column(SQLEnum(EvidenceType), default=EvidenceType.OTHER)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Metadata
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    uploaded_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="evidence", foreign_keys=[engagement_id])
    findings: Mapped[List["Finding"]] = relationship("Finding", secondary=finding_evidence_association, back_populates="evidence")


class ImportLog(Base):
    """Log of artifact imports"""
    __tablename__ = "import_logs"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey('engagements.id'), nullable=False)
    
    # Import details
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # nmap, nessus, zap
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    
    # Results
    imported_assets: Mapped[int] = mapped_column(Integer, default=0)
    imported_services: Mapped[int] = mapped_column(Integer, default=0)
    imported_findings: Mapped[int] = mapped_column(Integer, default=0)
    out_of_scope_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Status
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    warnings: Mapped[List[str]] = mapped_column(JSON, default=list)
    
    # Metadata
    imported_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    imported_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="imports")


class OSINTResult(Base):
    """OSINT lookup results"""
    __tablename__ = "osint_results"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    engagement_id: Mapped[int] = mapped_column(Integer, ForeignKey('engagements.id'), nullable=False)
    
    # Lookup details
    lookup_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # wayback, whois, hunter
    target: Mapped[str] = mapped_column(String(500), nullable=False, index=True)  # domain, URL, etc.
    
    # Results (stored as JSON for flexibility)
    raw_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    parsed_data: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
    
    # Metadata
    queried_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    queried_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Relationships
    engagement: Mapped["Engagement"] = relationship("Engagement", back_populates="osint_results")
