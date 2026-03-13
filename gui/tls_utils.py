"""TLS certificate utilities for FAROSINT"""
import os
import subprocess
from pathlib import Path

TLS_DIR = Path.home() / '.farosint' / 'tls'

def ensure_tls_dir():
    TLS_DIR.mkdir(parents=True, exist_ok=True)

def cert_path():
    return TLS_DIR / 'farosint.crt'

def key_path():
    return TLS_DIR / 'farosint.key'

def csr_path():
    return TLS_DIR / 'farosint.csr'

def cert_exists():
    return cert_path().exists() and key_path().exists()

def generate_self_signed(hostname='farosint-workstation'):
    """Generate self-signed cert + key. Returns True on success."""
    ensure_tls_dir()
    subj = f'/CN={hostname}/O=FAROSINT/OU=Security/C=AR'
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', str(key_path()),
        '-out', str(cert_path()),
        '-days', '3650',
        '-nodes', '-subj', subj
    ]
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0

def generate_csr(hostname='farosint-workstation'):
    """Generate private key + CSR for CA signing. Returns CSR bytes or None."""
    ensure_tls_dir()
    subj = f'/CN={hostname}/O=FAROSINT/OU=Security/C=AR'
    # Generate key
    key_cmd = ['openssl', 'genrsa', '-out', str(key_path()), '2048']
    subprocess.run(key_cmd, capture_output=True)
    # Generate CSR
    csr_cmd = [
        'openssl', 'req', '-new',
        '-key', str(key_path()),
        '-out', str(csr_path()),
        '-subj', subj
    ]
    result = subprocess.run(csr_cmd, capture_output=True)
    if result.returncode == 0:
        return csr_path().read_bytes()
    return None

def import_signed_cert(cert_bytes):
    """Import a CA-signed certificate. Returns True on success."""
    ensure_tls_dir()
    try:
        cert_path().write_bytes(cert_bytes)
        # Verify it matches the key
        verify = subprocess.run(
            ['openssl', 'verify', str(cert_path())],
            capture_output=True
        )
        return True
    except Exception:
        return False

def get_cert_info():
    """Return dict with cert expiry, issuer, subject. None if no cert."""
    if not cert_exists():
        return None
    result = subprocess.run(
        ['openssl', 'x509', '-in', str(cert_path()), '-noout',
         '-subject', '-issuer', '-enddate'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    info = {}
    for line in result.stdout.strip().split('\n'):
        if line.startswith('subject='):
            info['subject'] = line.split('=', 1)[1].strip()
        elif line.startswith('issuer='):
            info['issuer'] = line.split('=', 1)[1].strip()
            info['type'] = 'Self-signed' if info['subject'] == info['issuer'] else 'CA-signed'
        elif line.startswith('notAfter='):
            info['expires'] = line.split('=', 1)[1].strip()
    return info
