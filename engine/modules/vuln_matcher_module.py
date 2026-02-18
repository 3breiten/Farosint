#!/usr/bin/env python3
"""
FAROSINT Vulnerability Matcher Module
Correlación de servicios/versiones con CVEs de NVD + base local de fallback
"""

import json
import re
import time
import requests
from datetime import datetime, timedelta
from .base_module import BaseModule


# ============================================================
# Base local de CVEs para servicios comunes.
# Se usa como FALLBACK cuando NVD API no responde.
# Formato: {producto_lower: {version_prefix: [cves]}}
# ============================================================
_LOCAL_CVE_DB = {
    'openssh': {
        '7.9': [
            {'id': 'CVE-2018-20685', 'cvss_score': 5.3, 'severity': 'MEDIUM',
             'description': 'In OpenSSH 7.9, scp.c in the scp client allows remote SSH servers to bypass intended access restrictions via the filename of . or an empty filename.'},
            {'id': 'CVE-2019-6109', 'cvss_score': 6.8, 'severity': 'MEDIUM',
             'description': 'An issue was discovered in OpenSSH 7.9. Due to missing character encoding in the progress display, a malicious server could employ crafted object names to manipulate the client output.'},
            {'id': 'CVE-2019-6110', 'cvss_score': 6.8, 'severity': 'MEDIUM',
             'description': 'In OpenSSH 7.9, due to accepting and displaying arbitrary stderr output from the server, a malicious server can manipulate the client output.'},
            {'id': 'CVE-2019-6111', 'cvss_score': 5.9, 'severity': 'MEDIUM',
             'description': 'An issue was discovered in OpenSSH 7.9. Due to the scp implementation being derived from 1983 rcp, the server chooses which files/directories are sent to the client.'},
            {'id': 'CVE-2019-16905', 'cvss_score': 7.8, 'severity': 'HIGH',
             'description': 'OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a pre-authentication integer overflow in XMSS key parsing.'},
        ],
        '7.4': [
            {'id': 'CVE-2017-15906', 'cvss_score': 5.3, 'severity': 'MEDIUM',
             'description': 'The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly prevent write operations in read-only mode.'},
            {'id': 'CVE-2018-15473', 'cvss_score': 5.3, 'severity': 'MEDIUM',
             'description': 'OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user.'},
        ],
        '8.0': [
            {'id': 'CVE-2019-16905', 'cvss_score': 7.8, 'severity': 'HIGH',
             'description': 'OpenSSH 7.7 through 7.9 and 8.x before 8.1, when compiled with an experimental key type, has a pre-authentication integer overflow.'},
        ],
        '8.2': [
            {'id': 'CVE-2020-14145', 'cvss_score': 5.9, 'severity': 'MEDIUM',
             'description': 'The client side in OpenSSH 5.7 through 8.4, when using a default configuration, does not fully verify the host key during connection setup.'},
        ],
        '8.4': [
            {'id': 'CVE-2020-14145', 'cvss_score': 5.9, 'severity': 'MEDIUM',
             'description': 'The client side in OpenSSH 5.7 through 8.4, when using a default configuration, does not fully verify the host key during connection setup.'},
            {'id': 'CVE-2021-28041', 'cvss_score': 7.1, 'severity': 'HIGH',
             'description': 'ssh-agent in OpenSSH before 8.5 has a double free that may be relevant in a few less-common scenarios.'},
        ],
        '8.9': [
            {'id': 'CVE-2023-38408', 'cvss_score': 9.8, 'severity': 'CRITICAL',
             'description': 'The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution.'},
        ],
        '9.0': [
            {'id': 'CVE-2024-6387', 'cvss_score': 8.1, 'severity': 'HIGH',
             'description': 'RegreSSHion: RCE in OpenSSH server on glibc-based Linux systems. Race condition in sshd signal handler.'},
            {'id': 'CVE-2023-38408', 'cvss_score': 9.8, 'severity': 'CRITICAL',
             'description': 'The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path.'},
        ],
    },
    'apache httpd': {
        '2.4.38': [
            {'id': 'CVE-2019-0211', 'cvss_score': 7.8, 'severity': 'HIGH',
             'description': 'Apache HTTP Server 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in less-privileged child processes can execute arbitrary code with the privileges of the parent process.'},
            {'id': 'CVE-2019-0196', 'cvss_score': 5.3, 'severity': 'MEDIUM',
             'description': 'A vulnerability was found in Apache HTTP Server 2.4.17 to 2.4.38. Using fuzzed network input, the http/2 request handling could be made to access freed memory.'},
            {'id': 'CVE-2019-0197', 'cvss_score': 4.2, 'severity': 'MEDIUM',
             'description': 'A vulnerability was found in Apache HTTP Server 2.4.34 to 2.4.38. When HTTP/2 was enabled for a http: host or H2Upgrade was enabled for h2 on a https: host.'},
            {'id': 'CVE-2019-0220', 'cvss_score': 5.3, 'severity': 'MEDIUM',
             'description': 'A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. A bug in the handling of the normalization of URLs.'},
            {'id': 'CVE-2019-10081', 'cvss_score': 7.5, 'severity': 'HIGH',
             'description': 'HTTP/2 (2.4.20 through 2.4.39) very early pushes, for example configured with "H2PushResource", could lead to an overwrite of memory in the pushing request\'s pool.'},
            {'id': 'CVE-2019-10082', 'cvss_score': 9.1, 'severity': 'CRITICAL',
             'description': 'In Apache HTTP Server 2.4.18-2.4.39, using fuzzed network input, the http/2 session handling could be made to read memory after being freed.'},
            {'id': 'CVE-2019-10092', 'cvss_score': 6.1, 'severity': 'MEDIUM',
             'description': 'In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page.'},
            {'id': 'CVE-2019-10098', 'cvss_score': 6.1, 'severity': 'MEDIUM',
             'description': 'In Apache HTTP Server 2.4.0-2.4.39, redirects configured with mod_rewrite could be abused by encoding newlines.'},
        ],
        '2.4.41': [
            {'id': 'CVE-2020-1927', 'cvss_score': 6.1, 'severity': 'MEDIUM',
             'description': 'In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrite that were intended to be self-referential might be fooled by encoded newlines.'},
            {'id': 'CVE-2020-1934', 'cvss_score': 5.3, 'severity': 'MEDIUM',
             'description': 'In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may use uninitialized memory when proxying to a malicious FTP server.'},
        ],
        '2.4.46': [
            {'id': 'CVE-2021-26691', 'cvss_score': 9.8, 'severity': 'CRITICAL',
             'description': 'In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionHeader sent by an origin server could cause a heap overflow.'},
        ],
        '2.4.49': [
            {'id': 'CVE-2021-41773', 'cvss_score': 7.5, 'severity': 'HIGH',
             'description': 'Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49. A flaw was found in a change made to path normalization.'},
        ],
        '2.4.50': [
            {'id': 'CVE-2021-42013', 'cvss_score': 9.8, 'severity': 'CRITICAL',
             'description': 'Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49 and 2.4.50.'},
        ],
    },
    'nginx': {
        '1.14': [
            {'id': 'CVE-2019-9511', 'cvss_score': 7.5, 'severity': 'HIGH',
             'description': 'Some HTTP/2 implementations are vulnerable to window size manipulation, potentially leading to a denial of service.'},
            {'id': 'CVE-2019-9513', 'cvss_score': 7.5, 'severity': 'HIGH',
             'description': 'Some HTTP/2 implementations are vulnerable to resource loops, potentially leading to a denial of service.'},
        ],
        '1.16': [
            {'id': 'CVE-2019-9511', 'cvss_score': 7.5, 'severity': 'HIGH',
             'description': 'HTTP/2 Data Dribble vulnerability in nginx before 1.17.3.'},
        ],
        '1.18': [
            {'id': 'CVE-2021-23017', 'cvss_score': 7.7, 'severity': 'HIGH',
             'description': 'A security issue in nginx resolver could allow an attacker to cause 1-byte memory overwrite.'},
        ],
    },
    'microsoft iis httpd': {
        '10.0': [
            {'id': 'CVE-2021-31166', 'cvss_score': 9.8, 'severity': 'CRITICAL',
             'description': 'HTTP Protocol Stack Remote Code Execution Vulnerability in Microsoft IIS.'},
        ],
    },
    'vsftpd': {
        '3.0': [
            {'id': 'CVE-2015-1419', 'cvss_score': 5.0, 'severity': 'MEDIUM',
             'description': 'Unspecified vulnerability in vsftpd 3.0.2 allows remote attackers to bypass access restrictions.'},
        ],
    },
    'proftpd': {
        '1.3': [
            {'id': 'CVE-2019-12815', 'cvss_score': 9.8, 'severity': 'CRITICAL',
             'description': 'An arbitrary file copy vulnerability in mod_copy in ProFTPD up to 1.3.5b allows remote code execution.'},
        ],
    },
}


class VulnMatcherModule(BaseModule):
    """Módulo para correlacionar servicios con vulnerabilidades conocidas"""

    # Reintentos para NVD API (DNS intermitente)
    NVD_MAX_RETRIES = 3
    NVD_RETRY_DELAY = 5  # segundos entre reintentos

    def __init__(self, timeout=300, cache_manager=None):
        super().__init__("VulnMatcher", timeout, cache_manager)

        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_cache_ttl = 7 * 24 * 3600

    def run(self, services, **kwargs):
        """
        Correlacionar servicios detectados con CVEs conocidos.
        Intenta NVD API primero; si falla, usa base local.
        """
        if not services:
            self.log("No hay servicios para analizar")
            return {'services': [], 'total_cves': 0}

        self.log(f"Iniciando análisis de vulnerabilidades para {len(services)} servicios")

        severity_threshold = kwargs.get('severity_threshold', 'MEDIUM')
        max_age_days = kwargs.get('max_age_days', 365)

        results = {
            'services': [],
            'total_cves': 0,
            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }

        for service in services:
            service_name = service.get('name', '')
            service_version = service.get('version', '')

            if not service_name:
                continue

            self.log(f"Analizando: {service_name} {service_version}")

            # Intentar NVD API (con reintentos)
            cves = self._search_cves(
                service_name, service_version,
                max_age_days, severity_threshold
            )

            # Fallback: base local si NVD no devuelve nada
            if not cves:
                cves = self._search_local_cves(
                    service_name, service_version, severity_threshold
                )

            if cves:
                results['services'].append({
                    'name': service_name,
                    'version': service_version,
                    'port': service.get('port'),
                    'cves': cves,
                    'cve_count': len(cves)
                })

                results['total_cves'] += len(cves)

                for cve in cves:
                    severity = cve.get('severity', 'UNKNOWN')
                    if severity in results['by_severity']:
                        results['by_severity'][severity] += 1

        self.log(f"Análisis completado: {results['total_cves']} CVEs encontrados")
        return results

    def _search_cves(self, product_name, version, max_age_days, severity_threshold):
        """Buscar CVEs en NVD con reintentos."""
        cache_key = f"{product_name}:{version}:{max_age_days}:{severity_threshold}"
        cached = self.check_cache(cache_key, {})
        if cached:
            self.log(f"Usando CVEs cacheados para {product_name}")
            return cached

        product_clean = self._clean_product_name(product_name)

        params = {
            'keywordSearch': product_clean,
            'resultsPerPage': 50
        }
        if max_age_days:
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            params['pubStartDate'] = cutoff_date.strftime('%Y-%m-%dT00:00:00.000')

        # Reintentos con delay (DNS intermitente)
        last_error = None
        for attempt in range(1, self.NVD_MAX_RETRIES + 1):
            try:
                self.log(f"Consultando NVD API: {product_clean} (intento {attempt}/{self.NVD_MAX_RETRIES})")

                response = requests.get(
                    self.nvd_api_base,
                    params=params,
                    timeout=30,
                    headers={'User-Agent': 'FAROSINT/1.0'}
                )

                if response.status_code != 200:
                    self.log(f"NVD API HTTP {response.status_code}", "WARNING")
                    last_error = f"HTTP {response.status_code}"
                    if attempt < self.NVD_MAX_RETRIES:
                        time.sleep(self.NVD_RETRY_DELAY)
                    continue

                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                cves = []
                for vuln in vulnerabilities:
                    cve = self._parse_cve(vuln)
                    if not cve:
                        continue
                    if not self._meets_severity_threshold(cve.get('severity'), severity_threshold):
                        continue
                    if version and not self._version_matches(cve, product_name, version):
                        continue
                    cves.append(cve)

                if cves:
                    self.update_cache(cache_key, cves, {}, ttl=self.cve_cache_ttl)

                return cves

            except (requests.ConnectionError, requests.Timeout) as e:
                last_error = str(e)[:100]
                if attempt < self.NVD_MAX_RETRIES:
                    self.log(f"NVD API fallo (intento {attempt}), reintentando en {self.NVD_RETRY_DELAY}s...", "WARNING")
                    time.sleep(self.NVD_RETRY_DELAY)
                continue

            except Exception as e:
                self.log(f"Error buscando CVEs: {str(e)}", "ERROR")
                return []

        # Agotados los reintentos
        print(f"  [CVE Lookup] WARNING: NVD API inaccesible para {product_name} "
              f"después de {self.NVD_MAX_RETRIES} intentos ({last_error})")
        print(f"  [CVE Lookup] Usando base local de CVEs como fallback")
        return []

    def _search_local_cves(self, product_name, version, severity_threshold):
        """Buscar CVEs en la base local (fallback offline)."""
        product_key = self._clean_product_name(product_name)

        # Buscar el producto en la base local
        product_cves = _LOCAL_CVE_DB.get(product_key)
        if not product_cves:
            return []

        # Extraer version base (ej: "7.9p1 Debian 10+deb10u2" -> "7.9")
        version_base = self._extract_version_base(version)

        cves = product_cves.get(version_base, [])
        if not cves:
            # Intentar match parcial (ej: "2.4.38" -> buscar en "2.4")
            version_major_minor = '.'.join(version_base.split('.')[:2]) if '.' in version_base else version_base
            cves = product_cves.get(version_major_minor, [])

        if not cves:
            return []

        # Filtrar por severidad threshold
        filtered = []
        for cve in cves:
            if self._meets_severity_threshold(cve.get('severity'), severity_threshold):
                # Agregar campos faltantes para compatibilidad
                filtered.append({
                    'id': cve['id'],
                    'description': cve.get('description', ''),
                    'cvss_score': cve.get('cvss_score', 0.0),
                    'severity': cve.get('severity', 'UNKNOWN'),
                    'published': '',
                    'modified': '',
                    'url': f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                    'source': 'local_db',
                })

        if filtered:
            self.log(f"Base local: {len(filtered)} CVEs para {product_name} {version}")
            print(f"  [CVE Lookup] Base local: {len(filtered)} CVEs conocidos para {product_name} {version_base}")

        return filtered

    def _extract_version_base(self, version):
        """Extraer versión base numérica (ej: '7.9p1 Debian 10+deb10u2' -> '7.9')."""
        match = re.match(r'(\d+\.\d+(?:\.\d+)?)', version)
        return match.group(1) if match else version

    def _parse_cve(self, vuln_data):
        """Parsear datos de CVE desde respuesta de NVD."""
        try:
            cve_data = vuln_data.get('cve', {})
            cve_id = cve_data.get('id', '')

            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            metrics = cve_data.get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'

            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
                severity = self._cvss2_to_severity(cvss_score)

            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')

            return {
                'id': cve_id,
                'description': description[:500],
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'modified': modified,
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            }

        except Exception as e:
            self.log(f"Error parseando CVE: {str(e)}", "WARNING")
            return None

    def _clean_product_name(self, product_name):
        """Limpiar nombre de producto para búsqueda."""
        clean = re.sub(r'[^\w\s]', ' ', product_name)
        clean = ' '.join(clean.split())
        return clean.lower()

    def _meets_severity_threshold(self, severity, threshold):
        """Verificar si la severidad cumple el threshold."""
        severity_levels = {
            'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4
        }
        return severity_levels.get(severity, 0) >= severity_levels.get(threshold, 0)

    def _version_matches(self, cve, product_name, version):
        """Verificar si la versión está afectada (match optimista)."""
        return True

    def _cvss2_to_severity(self, score):
        """Convertir CVSS v2 score a severidad."""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
