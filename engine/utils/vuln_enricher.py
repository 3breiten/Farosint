#!/usr/bin/env python3
"""
FAROSINT Vulnerability Enricher
Enriquece vulnerabilidades con datos de APIs externas (NVD, etc.)
"""

import requests
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

class VulnEnricher:
    """Enriquecedor de vulnerabilidades"""

    def __init__(self, cache_dir=None):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".farosint" / "vuln_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(days=7)  # Cache por 7 días

    def _get_cache_path(self, cve_id):
        """Obtener ruta del cache para un CVE"""
        return self.cache_dir / f"{cve_id}.json"

    def _is_cache_valid(self, cache_path):
        """Verificar si el cache es válido"""
        if not cache_path.exists():
            return False

        mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
        return datetime.now() - mtime < self.cache_ttl

    def enrich_cve(self, cve_id):
        """
        Enriquecer un CVE con datos de NVD

        Args:
            cve_id: ID del CVE (ej: CVE-2024-1234)

        Returns:
            Dict con datos enriquecidos o None si falla
        """
        if not cve_id or not cve_id.startswith('CVE-'):
            return None

        # Verificar cache
        cache_path = self._get_cache_path(cve_id)
        if self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except:
                pass

        # Consultar NVD API
        try:
            url = f"{self.nvd_api_base}?cveId={cve_id}"
            headers = {
                'User-Agent': 'FAROSINT/1.0 (Security Research Tool)'
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()

                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln_data = data['vulnerabilities'][0]['cve']

                    # Extraer información relevante
                    enriched = {
                        'cve_id': cve_id,
                        'description': self._extract_description(vuln_data),
                        'cvss': self._extract_cvss(vuln_data),
                        'references': self._extract_references(vuln_data),
                        'published': vuln_data.get('published', ''),
                        'last_modified': vuln_data.get('lastModified', ''),
                        'cached_at': datetime.now().isoformat()
                    }

                    # Guardar en cache
                    try:
                        with open(cache_path, 'w') as f:
                            json.dump(enriched, f, indent=2)
                    except:
                        pass

                    return enriched

            elif response.status_code == 403:
                print(f"NVD API rate limit reached for {cve_id}")
                return None

        except requests.exceptions.Timeout:
            print(f"Timeout querying NVD for {cve_id}")
        except Exception as e:
            print(f"Error querying NVD for {cve_id}: {str(e)}")

        return None

    def _extract_description(self, vuln_data):
        """Extraer descripción en inglés"""
        try:
            descriptions = vuln_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    return desc.get('value', '')
        except:
            pass
        return ''

    def _extract_cvss(self, vuln_data):
        """Extraer CVSS scores"""
        cvss_data = {}

        try:
            metrics = vuln_data.get('metrics', {})

            # CVSS v3.x (preferido)
            if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                cvss = metrics['cvssMetricV31'][0]['cvssData']
                cvss_data = {
                    'version': '3.1',
                    'score': cvss.get('baseScore', 0),
                    'severity': cvss.get('baseSeverity', 'UNKNOWN'),
                    'vector': cvss.get('vectorString', '')
                }
            elif 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                cvss = metrics['cvssMetricV30'][0]['cvssData']
                cvss_data = {
                    'version': '3.0',
                    'score': cvss.get('baseScore', 0),
                    'severity': cvss.get('baseSeverity', 'UNKNOWN'),
                    'vector': cvss.get('vectorString', '')
                }
            # CVSS v2 (legacy)
            elif 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
                cvss = metrics['cvssMetricV2'][0]['cvssData']
                cvss_data = {
                    'version': '2.0',
                    'score': cvss.get('baseScore', 0),
                    'severity': self._cvss2_to_severity(cvss.get('baseScore', 0)),
                    'vector': cvss.get('vectorString', '')
                }
        except:
            pass

        return cvss_data

    def _cvss2_to_severity(self, score):
        """Convertir CVSS v2 score a severidad"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _extract_references(self, vuln_data):
        """Extraer referencias útiles"""
        refs = []

        try:
            references = vuln_data.get('references', [])

            # Priorizar referencias útiles
            priority_sources = [
                'exploit-db.com',
                'github.com',
                'packetstormsecurity.com',
                'seclists.org',
                'securityfocus.com',
                'fortiguard.com',
                'pentest-tools.com'
            ]

            for ref in references[:10]:  # Máximo 10 referencias
                url = ref.get('url', '')
                tags = ref.get('tags', [])

                # Calcular prioridad
                priority = 0
                for source in priority_sources:
                    if source in url.lower():
                        priority = 10
                        break

                if 'Exploit' in tags or 'exploit' in url.lower():
                    priority += 5
                if 'Patch' in tags or 'patch' in url.lower():
                    priority += 3

                refs.append({
                    'url': url,
                    'tags': tags,
                    'priority': priority
                })

            # Ordenar por prioridad
            refs.sort(key=lambda x: x['priority'], reverse=True)

        except:
            pass

        return refs

    def enrich_vulnerability_batch(self, vulnerabilities, delay=0.6):
        """
        Enriquecer un lote de vulnerabilidades

        Args:
            vulnerabilities: Lista de vulnerabilidades con campo 'cve'
            delay: Delay entre peticiones para respetar rate limit (segundos)

        Returns:
            Dict mapping CVE ID -> datos enriquecidos
        """
        enriched = {}

        for vuln in vulnerabilities:
            cve_id = vuln.get('cve')
            if not cve_id:
                continue

            # Enriquecer
            data = self.enrich_cve(cve_id)
            if data:
                enriched[cve_id] = data

            # Rate limiting (NVD limita a ~5 req/segundo sin API key)
            time.sleep(delay)

        return enriched
