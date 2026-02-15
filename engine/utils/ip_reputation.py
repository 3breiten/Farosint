#!/usr/bin/env python3
"""
FAROSINT IP Reputation Checker
Verifica reputación de IPs usando AbuseIPDB y otras fuentes
"""

import requests
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

class IPReputationChecker:
    """Checker de reputación de IPs"""

    def __init__(self, abuseipdb_key=None, cache_dir=None):
        """
        Inicializar IP Reputation Checker

        Args:
            abuseipdb_key: API key de AbuseIPDB (opcional)
            cache_dir: Directorio para caché
        """
        self.abuseipdb_key = abuseipdb_key
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"

        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".farosint" / "ip_reputation_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(days=1)  # Cache por 1 día

    def _get_cache_path(self, ip):
        """Obtener ruta de caché para una IP"""
        return self.cache_dir / f"{ip}.json"

    def _is_cache_valid(self, cache_path):
        """Verificar si el cache es válido"""
        if not cache_path.exists():
            return False

        mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
        return datetime.now() - mtime < self.cache_ttl

    def check_ip(self, ip_address):
        """
        Verificar reputación de una IP

        Args:
            ip_address: Dirección IP a verificar

        Returns:
            Dict con información de reputación
        """
        # Verificar cache
        cache_path = self._get_cache_path(ip_address)
        if self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except:
                pass

        # Datos base
        reputation = {
            'ip': ip_address,
            'is_malicious': False,
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'last_reported': None,
            'country': '',
            'isp': '',
            'usage_type': '',
            'is_public': self._is_public_ip(ip_address),
            'sources': [],
            'cached_at': datetime.now().isoformat()
        }

        # Si no es IP pública, no tiene sentido verificar reputación
        if not reputation['is_public']:
            self._save_cache(ip_address, reputation)
            return reputation

        # Verificar con AbuseIPDB si tenemos API key
        if self.abuseipdb_key:
            abuseipdb_data = self._check_abuseipdb(ip_address)
            if abuseipdb_data:
                reputation.update(abuseipdb_data)
                reputation['sources'].append('AbuseIPDB')

        # Guardar en cache
        self._save_cache(ip_address, reputation)

        return reputation

    def _check_abuseipdb(self, ip_address):
        """
        Verificar IP en AbuseIPDB

        Args:
            ip_address: IP a verificar

        Returns:
            Dict con datos de AbuseIPDB o None
        """
        if not self.abuseipdb_key:
            return None

        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }

            response = requests.get(
                self.abuseipdb_url,
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                if 'data' in data:
                    ip_data = data['data']

                    return {
                        'abuse_confidence_score': ip_data.get('abuseConfidenceScore', 0),
                        'total_reports': ip_data.get('totalReports', 0),
                        'last_reported': ip_data.get('lastReportedAt', None),
                        'country': ip_data.get('countryCode', ''),
                        'isp': ip_data.get('isp', ''),
                        'usage_type': ip_data.get('usageType', ''),
                        'is_malicious': ip_data.get('abuseConfidenceScore', 0) > 50,
                        'is_whitelisted': ip_data.get('isWhitelisted', False),
                        'is_tor': ip_data.get('isTor', False)
                    }

            elif response.status_code == 429:
                print(f"AbuseIPDB rate limit alcanzado para {ip_address}")

        except requests.exceptions.Timeout:
            print(f"Timeout consultando AbuseIPDB para {ip_address}")
        except Exception as e:
            print(f"Error consultando AbuseIPDB para {ip_address}: {str(e)}")

        return None

    def _is_public_ip(self, ip):
        """
        Verificar si una IP es pública (no privada/local)

        Args:
            ip: Dirección IP

        Returns:
            Bool
        """
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        except:
            return False

    def _save_cache(self, ip, data):
        """Guardar en caché"""
        try:
            cache_path = self._get_cache_path(ip)
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error guardando caché: {e}")

    def check_multiple_ips(self, ip_list):
        """
        Verificar múltiples IPs

        Args:
            ip_list: Lista de IPs

        Returns:
            Dict mapping IP -> reputación
        """
        results = {}

        for ip in ip_list:
            reputation = self.check_ip(ip)
            results[ip] = reputation

            # Rate limiting (1000 req/día con plan free = ~1 req cada 90 segundos)
            # Usar 2 segundos para ser conservador
            if self.abuseipdb_key:
                time.sleep(2.0)

        return results

    def get_malicious_ips(self, reputation_results):
        """
        Filtrar IPs maliciosas de resultados

        Args:
            reputation_results: Dict de resultados de reputación

        Returns:
            Lista de IPs consideradas maliciosas
        """
        malicious = []

        for ip, reputation in reputation_results.items():
            if reputation.get('is_malicious', False):
                malicious.append({
                    'ip': ip,
                    'confidence': reputation.get('abuse_confidence_score', 0),
                    'reports': reputation.get('total_reports', 0),
                    'isp': reputation.get('isp', ''),
                    'country': reputation.get('country', '')
                })

        # Ordenar por confidence score
        malicious.sort(key=lambda x: x['confidence'], reverse=True)

        return malicious

    def format_reputation_summary(self, reputation):
        """
        Formatear resumen de reputación

        Args:
            reputation: Dict de reputación

        Returns:
            String con resumen
        """
        lines = []

        lines.append(f"IP: {reputation['ip']}")

        if not reputation['is_public']:
            lines.append("  Estado: IP Privada/Local (no verificada)")
            return '\n'.join(lines)

        status = "MALICIOSA" if reputation['is_malicious'] else "Limpia"
        lines.append(f"  Estado: {status}")
        lines.append(f"  Confidence Score: {reputation['abuse_confidence_score']}%")
        lines.append(f"  Total Reportes: {reputation['total_reports']}")

        if reputation['country']:
            lines.append(f"  País: {reputation['country']}")

        if reputation['isp']:
            lines.append(f"  ISP: {reputation['isp']}")

        if reputation['usage_type']:
            lines.append(f"  Tipo: {reputation['usage_type']}")

        if reputation['sources']:
            lines.append(f"  Fuentes: {', '.join(reputation['sources'])}")

        return '\n'.join(lines)
