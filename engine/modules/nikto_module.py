#!/usr/bin/env python3
"""
FAROSINT Nikto Module
Scanner de vulnerabilidades web: misconfigs, versiones inseguras, archivos peligrosos
"""

import subprocess
import json
import re
from pathlib import Path
from .base_module import BaseModule


NIKTO_PATH = Path.home() / "tools" / "nikto" / "program" / "nikto.pl"


class NiktoModule(BaseModule):
    """Módulo para Nikto - scanner de vulnerabilidades web"""

    def __init__(self, timeout=300, cache_manager=None):
        super().__init__("Nikto", timeout, cache_manager)

    def run(self, target_url, **kwargs):
        """
        Ejecutar Nikto contra una URL

        Args:
            target_url: URL completa (http://host:port)

        Returns:
            Lista de findings de Nikto
        """
        self.log(f"Iniciando scan Nikto: {target_url}")

        if not NIKTO_PATH.exists():
            self.log("Nikto no encontrado en tools/", "WARNING")
            return []

        try:
            cmd = [
                'perl', str(NIKTO_PATH),
                '-h', target_url,
                '-Format', 'json',
                '-output', '/dev/stdout',
                '-nointeractive',
                '-maxtime', str(min(self.timeout, 180)),  # máx 3 min por URL
                '-Tuning', 'x',   # todos los tests excepto DOS
            ]

            self.log(f"Ejecutando: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30
            )

            return self._parse_output(result.stdout, result.stderr, target_url)

        except subprocess.TimeoutExpired:
            self.log(f"Timeout después de {self.timeout}s", "WARNING")
            return []
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            return []

    def _parse_output(self, stdout, stderr, target_url):
        """Parsear output JSON de Nikto"""
        findings = []

        # Intentar JSON
        try:
            json_match = re.search(r'\{.*\}', stdout, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                for host in data.get('host', []):
                    for item in host.get('vulnerabilities', []):
                        osvdb = item.get('id', '')
                        desc = item.get('msg', '')
                        method = item.get('method', 'GET')
                        uri = item.get('url', '')

                        severity = self._classify_severity(desc, osvdb)

                        findings.append({
                            'name': f"Nikto: {desc[:80]}",
                            'severity': severity,
                            'host': target_url,
                            'matched_at': f"{target_url}{uri}",
                            'cve': self._extract_cve(desc),
                            'cvss_score': self._severity_to_cvss(severity),
                            'template': f'nikto-{osvdb}',
                            'description': desc,
                            'tags': ['nikto', 'web', method.lower()],
                            'references': {},
                            'remediation': {'steps': ['Revisar configuración del servidor web', 'Actualizar a versión reciente']}
                        })
                self.log(f"Nikto encontró {len(findings)} issues en {target_url}")
                return findings
        except Exception:
            pass

        # Fallback: parseo de texto
        return self._parse_text(stdout, target_url)

    # Líneas de Nikto que son informativas/status, no vulnerabilidades
    _NOISE_PATTERNS = [
        'target ip:', 'target hostname:', 'target port:', 'start time:',
        'end time:', 'host(s) tested', 'requests:', 'error(s) and',
        'no cgi directories found', 'ssl info:', 'server:',
        'multiple ips found', 'root page / redirects to', 'multiple index files found',
        'scan terminated', 'server is using a wildcard certificate',
        'no banner retrieved', 'ip address found in the',
        # Nikto genera permutaciones del hostname para buscar backups.
        # Son probes especulativos, no hallazgos confirmados.
        'potentially interesting',
        # Headers custom/CDN que no son vulnerabilidades
        'uncommon header',
        # Info SSL/alt-svc que no es una vuln
        'an alt-svc header was found',
    ]

    def _is_noise(self, desc):
        """Detectar si la línea es informativa (no una vulnerabilidad real)"""
        desc_lower = desc.lower()
        return any(p in desc_lower for p in self._NOISE_PATTERNS)

    def _parse_text(self, stdout, target_url):
        """Parseo de texto del output de Nikto"""
        findings = []
        for line in stdout.split('\n'):
            if line.startswith('+ ') and len(line) > 3:
                desc = line[2:].strip()
                if not desc or desc.startswith('Target') or desc.startswith('Start'):
                    continue
                if self._is_noise(desc):
                    continue
                severity = self._classify_severity(desc, '')
                findings.append({
                    'name': f"Nikto: {desc[:80]}",
                    'severity': severity,
                    'host': target_url,
                    'matched_at': target_url,
                    'cve': self._extract_cve(desc),
                    'cvss_score': self._severity_to_cvss(severity),
                    'template': 'nikto-finding',
                    'description': desc,
                    'tags': ['nikto', 'web'],
                    'references': {},
                    'remediation': {'steps': ['Revisar configuración del servidor web']}
                })
        self.log(f"Nikto (texto): {len(findings)} issues")
        return findings

    def _classify_severity(self, description, osvdb_id):
        """Clasificar severidad basada en descripción"""
        desc_lower = description.lower()
        if any(k in desc_lower for k in ['rce', 'remote code', 'command injection']):
            return 'critical'
        if any(k in desc_lower for k in ['xss', 'sql injection', 'traversal', 'lfi', 'rfi', 'csrf']):
            return 'high'
        if any(k in desc_lower for k in [
            'requires authentication', 'no creds found',
            'information disclosure', 'debug', 'password',
        ]):
            return 'medium'
        if any(k in desc_lower for k in ['header', 'missing', 'cookie', 'outdated', 'appears to be']):
            return 'low'
        return 'low'

    def _extract_cve(self, description):
        """Extraer CVE de la descripción"""
        cve_match = re.search(r'CVE-\d{4}-\d+', description, re.IGNORECASE)
        return cve_match.group(0).upper() if cve_match else None

    def _severity_to_cvss(self, severity):
        return {'critical': 9.0, 'high': 7.5, 'medium': 5.0, 'low': 3.0}.get(severity, 5.0)
