"""Test hashing utilities"""
import pytest
from pathlib import Path
from app.services.hashing import calculate_sha256, calculate_sha256_from_bytes, generate_hash_manifest


def test_sha256_from_bytes():
    """Test hashing bytes"""
    data = b"Hello, World!"
    hash_result = calculate_sha256_from_bytes(data)
    
    # Known SHA-256 of "Hello, World!"
    expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    assert hash_result == expected


def test_generate_hash_manifest():
    """Test manifest generation"""
    files = {
        "file1.txt": "abc123",
        "file2.txt": "def456",
        "subdir/file3.txt": "ghi789"
    }
    
    manifest = generate_hash_manifest(files)
    
    lines = manifest.split("\n")
    assert len(lines) == 3
    assert "abc123  file1.txt" in lines
    assert "def456  file2.txt" in lines
    assert "ghi789  subdir/file3.txt" in lines
