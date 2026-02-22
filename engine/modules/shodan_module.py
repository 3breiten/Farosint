"""
FAROSINT - Shodan Module
Enriquecimiento de resultados usando la API de Shodan.
"""
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ShodanModule:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._api = None

    def _get_api(self):
        if self._api is None:
            import shodan
            self._api = shodan.Shodan(self.api_key)
        return self._api

    def query_host(self, ip: str) -> Optional[Dict]:
        """Consulta Shodan para una IP específica."""
        try:
            api = self._get_api()
            result = api.host(ip)
            return self._parse_host(result)
        except Exception as e:
            logger.warning(f"[Shodan] Error consultando {ip}: {e}")
            return None

    def query_domain(self, domain: str) -> Optional[Dict]:
        """Consulta Shodan DNS para un dominio."""
        try:
            api = self._get_api()
            result = api.search(f'hostname:{domain}')
            hosts = []
            for match in result.get('matches', [])[:20]:
                hosts.append(self._parse_match(match))
            return {
                'domain': domain,
                'total': result.get('total', 0),
                'hosts': hosts
            }
        except Exception as e:
            logger.warning(f"[Shodan] Error consultando dominio {domain}: {e}")
            return None

    def _parse_host(self, data: Dict) -> Dict:
        ports = [item['port'] for item in data.get('data', [])]
        vulns = list(data.get('vulns', {}).keys())
        return {
            'ip':           data.get('ip_str', ''),
            'org':          data.get('org', ''),
            'isp':          data.get('isp', ''),
            'country':      data.get('country_name', ''),
            'city':         data.get('city', ''),
            'asn':          data.get('asn', ''),
            'os':           data.get('os', ''),
            'hostnames':    data.get('hostnames', []),
            'ports':        ports,
            'vulns':        vulns,
            'tags':         data.get('tags', []),
            'last_update':  data.get('last_update', ''),
        }

    def _parse_match(self, match: Dict) -> Dict:
        return {
            'ip':       match.get('ip_str', ''),
            'port':     match.get('port', ''),
            'org':      match.get('org', ''),
            'country':  match.get('location', {}).get('country_name', ''),
            'hostnames': match.get('hostnames', []),
            'product':  match.get('product', ''),
            'version':  match.get('version', ''),
            'vulns':    list(match.get('vulns', {}).keys()),
        }

    def enrich_scan(self, ips: List[str], domain: str = None) -> Dict:
        """
        Enriquece un escaneo consultando IPs y opcionalmente el dominio.
        Retorna dict con resultados agrupados.
        """
        results = {'hosts': {}, 'domain': None, 'new_vulns': []}

        for ip in ips:
            host_data = self.query_host(ip)
            if host_data:
                results['hosts'][ip] = host_data
                # Registrar CVEs nuevos encontrados por Shodan
                for cve in host_data.get('vulns', []):
                    results['new_vulns'].append({
                        'cve_id': cve,
                        'source': 'shodan',
                        'ip': ip,
                        'severity': 'high',  # Shodan no da severidad directa
                        'name': f'CVE detectado por Shodan en {ip}',
                        'description': f'Shodan detectó {cve} en el host {ip}.',
                    })

        if domain:
            results['domain'] = self.query_domain(domain)

        return results
