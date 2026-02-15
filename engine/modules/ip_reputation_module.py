#!/usr/bin/env python3
"""
FAROSINT IP Reputation Module
Análisis de reputación de IPs usando múltiples fuentes públicas
"""

import socket
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base_module import BaseModule

class IPReputationModule(BaseModule):
    """Módulo para análisis de reputación de IPs"""

    def __init__(self, timeout=300, cache_manager=None):
        super().__init__("IPReputation", timeout, cache_manager)

        # Fuentes de reputación (servicios públicos sin API key)
        self.reputation_sources = {
            'abuseipdb': {
                'enabled': False,  # Requiere API key
                'weight': 3
            },
            'virustotal': {
                'enabled': False,  # Requiere API key
                'weight': 3
            },
            'dnsbl': {
                'enabled': True,   # DNSBL público
                'weight': 2
            },
            'greynoise': {
                'enabled': False,  # Requiere API key
                'weight': 2
            }
        }

        # DNSBLs públicos (sin API key necesaria)
        self.dnsbl_providers = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'cbl.abuseat.org',
            'b.barracudacentral.org',
            'dnsbl.sorbs.net'
        ]

        # Caché extendido (24 horas)
        self.reputation_cache_ttl = 24 * 3600

    def run(self, targets, **kwargs):
        """
        Analizar reputación de IPs

        Args:
            targets: IP o lista de IPs a analizar
            **kwargs: Parámetros adicionales
                - parallel: Ejecutar checks en paralelo (default: True)
                - risk_threshold: Threshold de riesgo 0-10 (default: 5)

        Returns:
            Dict con resultados de reputación por IP
        """
        # Normalizar targets a lista
        if isinstance(targets, str):
            ips = [targets]
        else:
            ips = targets

        self.log(f"Iniciando análisis de reputación para {len(ips)} IPs")

        results = {
            'ips': [],
            'total_checked': 0,
            'flagged': 0
        }

        parallel = kwargs.get('parallel', True)
        risk_threshold = kwargs.get('risk_threshold', 5)

        if parallel and len(ips) > 1:
            # Análisis paralelo
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_ip = {
                    executor.submit(self._check_ip_reputation, ip, risk_threshold): ip
                    for ip in ips
                }

                for future in as_completed(future_to_ip):
                    ip_result = future.result()
                    if ip_result:
                        results['ips'].append(ip_result)
                        results['total_checked'] += 1

                        if ip_result.get('is_flagged', False):
                            results['flagged'] += 1
        else:
            # Análisis secuencial
            for ip in ips:
                ip_result = self._check_ip_reputation(ip, risk_threshold)
                if ip_result:
                    results['ips'].append(ip_result)
                    results['total_checked'] += 1

                    if ip_result.get('is_flagged', False):
                        results['flagged'] += 1

        self.log(f"Análisis completado: {results['flagged']}/{results['total_checked']} IPs flagged")
        return results

    def _check_ip_reputation(self, ip, risk_threshold):
        """
        Verificar reputación de una IP

        Args:
            ip: Dirección IP
            risk_threshold: Threshold de riesgo

        Returns:
            Dict con información de reputación
        """
        # Validar IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                self.log(f"Saltando IP privada/loopback: {ip}")
                return None
        except ValueError:
            self.log(f"IP inválida: {ip}", "WARNING")
            return None

        # Verificar caché
        cached = self.check_cache(ip, {})
        if cached:
            self.log(f"Usando reputación cacheada para {ip}")
            return cached

        self.log(f"Verificando reputación de: {ip}")

        # Inicializar resultado
        result = {
            'ip': ip,
            'risk_score': 0,
            'is_flagged': False,
            'sources': [],
            'categories': []
        }

        # Check DNSBL
        dnsbl_results = self._check_dnsbl(ip)
        if dnsbl_results:
            result['sources'].extend(dnsbl_results)

            # Calcular risk score basado en DNSBLs
            # Cada DNSBL que lista la IP suma 2 puntos
            result['risk_score'] = min(len(dnsbl_results) * 2, 10)

            # Extraer categorías
            categories = set()
            for dnsbl in dnsbl_results:
                if 'spam' in dnsbl['provider'].lower():
                    categories.add('spam')
                if 'abuse' in dnsbl['provider'].lower():
                    categories.add('abuse')
                if 'cbl' in dnsbl['provider'].lower():
                    categories.add('botnet')

            result['categories'] = list(categories)

        # Determinar si está flagged
        result['is_flagged'] = result['risk_score'] >= risk_threshold

        # Guardar en caché
        self.update_cache(ip, result, {}, ttl=self.reputation_cache_ttl)

        return result

    def _check_dnsbl(self, ip):
        """
        Verificar IP en DNSBLs públicos

        Args:
            ip: Dirección IP

        Returns:
            Lista de DNSBLs que listan la IP
        """
        results = []

        # Invertir IP para query DNSBL
        # Ejemplo: 1.2.3.4 -> 4.3.2.1.dnsbl.provider.com
        octets = ip.split('.')
        reversed_ip = '.'.join(reversed(octets))

        for provider in self.dnsbl_providers:
            try:
                query = f"{reversed_ip}.{provider}"

                # Intentar resolver el hostname
                # Si resuelve, significa que la IP está listada
                socket.gethostbyname(query)

                # IP está listada en este DNSBL
                results.append({
                    'provider': provider,
                    'status': 'listed',
                    'weight': 2
                })

                self.log(f"  {ip} listado en {provider}", "WARNING")

            except socket.gaierror:
                # IP no está listada (no resuelve)
                pass

            except Exception as e:
                self.log(f"Error verificando {provider}: {str(e)}", "WARNING")

        return results

    def _check_abuseipdb(self, ip, api_key):
        """
        Verificar IP en AbuseIPDB (requiere API key)

        Args:
            ip: Dirección IP
            api_key: API key de AbuseIPDB

        Returns:
            Dict con información de AbuseIPDB o None
        """
        if not api_key:
            return None

        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})

                abuse_score = data.get('abuseConfidenceScore', 0)
                is_whitelisted = data.get('isWhitelisted', False)
                usage_type = data.get('usageType', '')

                return {
                    'provider': 'AbuseIPDB',
                    'abuse_score': abuse_score,
                    'is_whitelisted': is_whitelisted,
                    'usage_type': usage_type,
                    'weight': 3
                }

        except Exception as e:
            self.log(f"Error verificando AbuseIPDB: {str(e)}", "WARNING")

        return None

    def _check_virustotal(self, ip, api_key):
        """
        Verificar IP en VirusTotal (requiere API key)

        Args:
            ip: Dirección IP
            api_key: API key de VirusTotal

        Returns:
            Dict con información de VirusTotal o None
        """
        if not api_key:
            return None

        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {
                'x-apikey': api_key
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})

                last_analysis = attributes.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)

                return {
                    'provider': 'VirusTotal',
                    'malicious_votes': malicious,
                    'suspicious_votes': suspicious,
                    'weight': 3
                }

        except Exception as e:
            self.log(f"Error verificando VirusTotal: {str(e)}", "WARNING")

        return None

    def format_results_summary(self, results):
        """
        Formatear resumen de resultados

        Args:
            results: Resultados del análisis

        Returns:
            String con resumen formateado
        """
        if not results or results.get('total_checked', 0) == 0:
            return "No se analizaron IPs"

        summary = []
        summary.append(f"\n{'='*60}")
        summary.append(f"IP REPUTATION - Resumen")
        summary.append(f"{'='*60}")
        summary.append(f"Total IPs analizadas: {results['total_checked']}")
        summary.append(f"IPs flagged: {results['flagged']}")

        if results['flagged'] > 0:
            summary.append(f"\nIPs con mala reputación:")

            flagged_ips = [ip for ip in results.get('ips', []) if ip.get('is_flagged', False)]

            for ip_data in flagged_ips:
                summary.append(f"\n  {ip_data['ip']} - Risk Score: {ip_data['risk_score']}/10")

                categories = ip_data.get('categories', [])
                if categories:
                    summary.append(f"    Categorías: {', '.join(categories)}")

                sources = ip_data.get('sources', [])
                if sources:
                    summary.append(f"    Listado en {len(sources)} DNSBLs:")
                    for source in sources[:3]:  # Mostrar top 3
                        summary.append(f"      - {source['provider']}")

        else:
            summary.append(f"\n✓ Todas las IPs tienen buena reputación")

        return '\n'.join(summary)

    def get_high_risk_ips(self, results, threshold=7):
        """
        Obtener lista de IPs de alto riesgo

        Args:
            results: Resultados del análisis
            threshold: Threshold de riesgo (default: 7)

        Returns:
            Lista de IPs de alto riesgo
        """
        high_risk = []

        for ip_data in results.get('ips', []):
            if ip_data.get('risk_score', 0) >= threshold:
                high_risk.append({
                    'ip': ip_data['ip'],
                    'risk_score': ip_data['risk_score'],
                    'categories': ip_data.get('categories', [])
                })

        return high_risk
