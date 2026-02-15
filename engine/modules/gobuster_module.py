#!/usr/bin/env python3
"""
FAROSINT Gobuster Module
Enumeración de directorios y archivos web por fuerza bruta
"""

import subprocess
import re
from pathlib import Path
from .base_module import BaseModule


# Wordlist compacta incluida - si no hay una del sistema
BUILTIN_WORDLIST = [
    'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'dashboard',
    'api', 'api/v1', 'api/v2', 'swagger', 'docs', 'backup', 'backups',
    'config', 'configuration', 'settings', '.git', '.env', '.htaccess',
    'robots.txt', 'sitemap.xml', 'web.config', 'phpinfo.php', 'info.php',
    'test', 'dev', 'staging', 'old', 'upload', 'uploads', 'files', 'data',
    'static', 'assets', 'images', 'img', 'css', 'js', 'fonts',
    'includes', 'inc', 'lib', 'src', 'app', 'application',
    'user', 'users', 'account', 'accounts', 'profile', 'register',
    'wp-content', 'wp-includes', 'wordpress', 'joomla', 'drupal',
    'shell', 'cmd', 'exec', 'webshell', 'pass', 'passwd', 'password',
    'db', 'database', 'sql', 'mysql', 'mongo', 'redis',
    'health', 'status', 'ping', 'metrics', 'monitor',
    'console', 'terminal', 'manager', 'management',
    '.DS_Store', 'Thumbs.db', 'desktop.ini',
]

# Rutas de wordlists del sistema
SYSTEM_WORDLISTS = [
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/dirb/wordlists/common.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
]


class GobusterModule(BaseModule):
    """Módulo para Gobuster - enumeración de directorios web"""

    def __init__(self, timeout=180, cache_manager=None):
        super().__init__("Gobuster", timeout, cache_manager)
        self.wordlist = self._find_wordlist()

    def _find_wordlist(self):
        """Buscar wordlist disponible en el sistema"""
        for wl in SYSTEM_WORDLISTS:
            if Path(wl).exists():
                return wl
        # Crear wordlist temporal
        tmp = Path('/tmp/farosint_gobuster_wordlist.txt')
        tmp.write_text('\n'.join(BUILTIN_WORDLIST))
        return str(tmp)

    def run(self, target_url, **kwargs):
        """
        Ejecutar gobuster dir contra una URL

        Returns:
            Lista de paths encontrados con sus status codes
        """
        self.log(f"Iniciando gobuster en: {target_url}")

        gobuster_bin = self.get_tool_path('gobuster')
        if not gobuster_bin:
            self.log("gobuster no encontrado", "WARNING")
            return []

        try:
            cmd = [
                gobuster_bin, 'dir',
                '-u', target_url,
                '-w', self.wordlist,
                '-t', '20',         # 20 threads
                '-q',               # quiet
                '--no-error',
                '-o', '/dev/stdout',
                '--timeout', '5s',
            ]

            self.log(f"Ejecutando gobuster con wordlist: {self.wordlist}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            return self._parse_output(result.stdout, target_url)

        except subprocess.TimeoutExpired:
            self.log(f"Timeout después de {self.timeout}s - resultados parciales", "WARNING")
            return []
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            return []

    def _parse_output(self, stdout, target_url):
        """Parsear output de gobuster"""
        findings = []

        for line in stdout.split('\n'):
            line = line.strip()
            if not line or line.startswith('Error') or line.startswith('='):
                continue

            # Formato: /path (Status: 200) [Size: 1234]
            match = re.match(r'^(/\S*)\s+\(Status:\s*(\d+)\)\s*(?:\[Size:\s*(\d+)\])?', line)
            if match:
                path = match.group(1)
                status = int(match.group(2))
                size = match.group(3) or '?'

                # Solo reportar paths interesantes
                if status in (200, 301, 302, 403, 500):
                    severity = self._classify_path(path, status)
                    findings.append({
                        'path': path,
                        'status_code': status,
                        'size': size,
                        'url': f"{target_url}{path}",
                        'severity': severity,
                        'name': f"Dir found: {path} [{status}]",
                        'host': target_url,
                        'matched_at': f"{target_url}{path}",
                        'cve': None,
                        'cvss_score': self._severity_to_cvss(severity),
                        'template': 'gobuster-dir',
                        'description': f"Directorio/archivo accesible: {target_url}{path} (HTTP {status}, Size: {size})",
                        'tags': ['gobuster', 'web', 'directory'],
                        'references': {},
                        'remediation': {'steps': ['Revisar si el recurso debe ser público', 'Configurar autenticación o restricción de acceso']}
                    })

        self.log(f"Gobuster encontró {len(findings)} paths en {target_url}")
        return findings

    def _classify_path(self, path, status):
        """Clasificar severidad del path encontrado"""
        path_lower = path.lower()
        if any(k in path_lower for k in ['.git', '.env', 'backup', 'db', 'sql', 'config', '.htpasswd', 'passwd']):
            return 'high'
        if any(k in path_lower for k in ['admin', 'phpmyadmin', 'shell', 'cmd', 'upload', 'webshell', 'console']):
            return 'high' if status == 200 else 'medium'
        if any(k in path_lower for k in ['login', 'api', 'dashboard', 'wp-admin', 'phpinfo', 'info.php']):
            return 'medium'
        return 'low'

    def _severity_to_cvss(self, severity):
        return {'high': 7.0, 'medium': 5.0, 'low': 3.0}.get(severity, 3.0)
