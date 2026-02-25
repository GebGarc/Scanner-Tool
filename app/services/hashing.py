"""File hashing and evidence management"""
import hashlib
from pathlib import Path
from typing import BinaryIO


def calculate_sha256(file_path: Path) -> str:
    """
    Calculate SHA-256 hash of a file
    
    Args:
        file_path: Path to file
        
    Returns:
        Hex digest of SHA-256 hash
    """
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()


def calculate_sha256_from_bytes(data: bytes) -> str:
    """
    Calculate SHA-256 hash of bytes
    
    Args:
        data: Bytes to hash
        
    Returns:
        Hex digest of SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


def calculate_sha256_from_stream(stream: BinaryIO) -> str:
    """
    Calculate SHA-256 hash from file stream
    
    Args:
        stream: Binary stream
        
    Returns:
        Hex digest of SHA-256 hash
    """
    sha256_hash = hashlib.sha256()
    
    # Read in chunks
    for byte_block in iter(lambda: stream.read(4096), b""):
        sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()


def generate_hash_manifest(files: dict[str, str]) -> str:
    """
    Generate a hash manifest file content
    
    Args:
        files: Dictionary mapping file paths to their SHA-256 hashes
        
    Returns:
        Manifest content (one line per file: hash filename)
    """
    lines = []
    for file_path, file_hash in sorted(files.items()):
        lines.append(f"{file_hash}  {file_path}")
    
    return "\n".join(lines)


def verify_hash_manifest(manifest_path: Path, base_dir: Path) -> dict[str, bool]:
    """
    Verify files against a hash manifest
    
    Args:
        manifest_path: Path to manifest file
        base_dir: Base directory for relative paths in manifest
        
    Returns:
        Dictionary mapping file paths to verification status (True = valid)
    """
    results = {}
    
    with open(manifest_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Parse: hash  filename
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            
            expected_hash, file_path = parts
            full_path = base_dir / file_path
            
            if not full_path.exists():
                results[file_path] = False
                continue
            
            actual_hash = calculate_sha256(full_path)
            results[file_path] = (actual_hash == expected_hash)
    
    return results
