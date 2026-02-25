"""Test scope validation"""
import pytest
from app.services.scope import ScopeValidator


def test_domain_exact_match():
    validator = ScopeValidator(domains=["example.com"])
    in_scope, reason = validator.is_domain_in_scope("example.com")
    assert in_scope
    assert "Exact match" in reason


def test_domain_wildcard_match():
    validator = ScopeValidator(domains=["*.example.com"])
    
    in_scope, _ = validator.is_domain_in_scope("sub.example.com")
    assert in_scope
    
    in_scope, _ = validator.is_domain_in_scope("deep.sub.example.com")
    assert in_scope
    
    in_scope, _ = validator.is_domain_in_scope("example.com")
    assert in_scope  # Root domain should match


def test_domain_out_of_scope():
    validator = ScopeValidator(domains=["example.com"])
    in_scope, reason = validator.is_domain_in_scope("attacker.com")
    assert not in_scope
    assert "not in allowlist" in reason


def test_ip_exact_match():
    validator = ScopeValidator(ips=["192.168.1.1"])
    in_scope, reason = validator.is_ip_in_scope("192.168.1.1")
    assert in_scope


def test_ip_cidr_match():
    validator = ScopeValidator(ips=["192.168.1.0/24"])
    
    in_scope, _ = validator.is_ip_in_scope("192.168.1.1")
    assert in_scope
    
    in_scope, _ = validator.is_ip_in_scope("192.168.1.254")
    assert in_scope
    
    in_scope, _ = validator.is_ip_in_scope("192.168.2.1")
    assert not in_scope


def test_url_scope():
    validator = ScopeValidator(
        domains=["example.com"],
        urls=["https://app.test.com"]
    )
    
    # Domain match
    in_scope, _ = validator.is_url_in_scope("https://example.com/path")
    assert in_scope
    
    # URL base match
    in_scope, _ = validator.is_url_in_scope("https://app.test.com/api/v1")
    assert in_scope
    
    # Out of scope
    in_scope, _ = validator.is_url_in_scope("https://attacker.com")
    assert not in_scope


def test_auto_detect():
    validator = ScopeValidator(
        domains=["example.com"],
        ips=["192.168.1.0/24"],
        urls=["https://app.example.com"]
    )
    
    # IP
    in_scope, target_type, _ = validator.check_target("192.168.1.1")
    assert in_scope
    assert target_type == "ip"
    
    # Domain
    in_scope, target_type, _ = validator.check_target("example.com")
    assert in_scope
    assert target_type == "domain"
    
    # URL
    in_scope, target_type, _ = validator.check_target("https://app.example.com/test")
    assert in_scope
    assert target_type == "url"
