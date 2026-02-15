#!/usr/bin/env python3
"""
FAROSINT Vulnerability Matcher Module
Correlación de servicios/versiones con CVEs de NVD
"""

import json
import re
import requests
from datetime import datetime, timedelta
from .base_module import BaseModule

class VulnMatcherModule(BaseModule):
    """Módulo para correlacionar servicios con vulnerabilidades conocidas"""

    def __init__(self, timeout=300, cache_manager=None):
        super().__init__("VulnMatcher", timeout, cache_manager)

        # API de NVD (National Vulnerability Database)
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Caché extendido para CVEs (7 días)
        self.cve_cache_ttl = 7 * 24 * 3600  # 7 días en segundos

    def run(self, services, **kwargs):
        """
        Correlacionar servicios detectados con CVEs conocidos

        Args:
            services: Lista de servicios detectados (de Nmap o WhatWeb)
                Formato: [{'name': 'Apache', 'version': '2.4.41', 'port': 80}, ...]
            **kwargs: Parámetros adicionales
                - severity_threshold: Severidad mínima (LOW, MEDIUM, HIGH, CRITICAL)
                - max_age_days: Edad máxima de CVEs en días (default: 365)

        Returns:
            Dict con vulnerabilidades encontradas por servicio
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

            # Buscar CVEs para este servicio
            cves = self._search_cves(
                service_name,
                service_version,
                max_age_days,
                severity_threshold
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

                # Contar por severidad
                for cve in cves:
                    severity = cve.get('severity', 'UNKNOWN')
                    if severity in results['by_severity']:
                        results['by_severity'][severity] += 1

        self.log(f"Análisis completado: {results['total_cves']} CVEs encontrados")
        return results

    def _search_cves(self, product_name, version, max_age_days, severity_threshold):
        """
        Buscar CVEs en NVD para un producto/versión

        Args:
            product_name: Nombre del producto
            version: Versión del producto
            max_age_days: Edad máxima de CVEs
            severity_threshold: Severidad mínima

        Returns:
            Lista de CVEs encontrados
        """
        # Generar cache key
        cache_key = f"{product_name}:{version}:{max_age_days}:{severity_threshold}"
        cached = self.check_cache(cache_key, {})

        if cached:
            self.log(f"Usando CVEs cacheados para {product_name}")
            return cached

        try:
            # Limpiar nombre del producto para query
            product_clean = self._clean_product_name(product_name)

            # Construir query
            params = {
                'keywordSearch': product_clean,
                'resultsPerPage': 50
            }

            # Filtrar por fecha si es necesario
            if max_age_days:
                cutoff_date = datetime.now() - timedelta(days=max_age_days)
                params['pubStartDate'] = cutoff_date.strftime('%Y-%m-%dT00:00:00.000')

            self.log(f"Consultando NVD API: {product_clean}")

            # Hacer request a NVD API
            response = requests.get(
                self.nvd_api_base,
                params=params,
                timeout=30,
                headers={'User-Agent': 'FAROSINT/1.0'}
            )

            if response.status_code != 200:
                self.log(f"Error en NVD API: {response.status_code}", "WARNING")
                return []

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])

            # Parsear y filtrar CVEs
            cves = []
            for vuln in vulnerabilities:
                cve = self._parse_cve(vuln)

                if not cve:
                    continue

                # Filtrar por severidad
                if not self._meets_severity_threshold(cve.get('severity'), severity_threshold):
                    continue

                # Filtrar por versión si es posible
                if version and not self._version_matches(cve, product_name, version):
                    continue

                cves.append(cve)

            # Guardar en caché (7 días)
            if cves:
                self.update_cache(cache_key, cves, {}, ttl=self.cve_cache_ttl)

            return cves

        except requests.Timeout:
            self.log(f"Timeout consultando NVD para {product_name}", "WARNING")
            return []

        except Exception as e:
            self.log(f"Error buscando CVEs: {str(e)}", "ERROR")
            return []

    def _parse_cve(self, vuln_data):
        """
        Parsear datos de CVE desde respuesta de NVD

        Args:
            vuln_data: Datos de vulnerabilidad de NVD API

        Returns:
            Dict con información del CVE o None
        """
        try:
            cve_data = vuln_data.get('cve', {})

            cve_id = cve_data.get('id', '')

            # Extraer descripción
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            # Extraer métricas (CVSS)
            metrics = vuln_data.get('cve', {}).get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'

            # Preferir CVSS v3.1
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Fallback a CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            # Fallback a CVSS v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]
                cvss_score = cvss_data.get('cvssData', {}).get('baseScore', 0.0)
                severity = self._cvss2_to_severity(cvss_score)

            # Extraer fechas
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')

            return {
                'id': cve_id,
                'description': description[:500],  # Limitar longitud
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
        """
        Limpiar nombre de producto para búsqueda en NVD

        Args:
            product_name: Nombre del producto raw

        Returns:
            Nombre limpio para búsqueda
        """
        # Remover caracteres especiales
        clean = re.sub(r'[^\w\s]', ' ', product_name)

        # Normalizar espacios
        clean = ' '.join(clean.split())

        return clean.lower()

    def _meets_severity_threshold(self, severity, threshold):
        """
        Verificar si la severidad cumple el threshold

        Args:
            severity: Severidad del CVE
            threshold: Threshold mínimo

        Returns:
            True si cumple, False si no
        """
        severity_levels = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4
        }

        sev_level = severity_levels.get(severity, 0)
        threshold_level = severity_levels.get(threshold, 0)

        return sev_level >= threshold_level

    def _version_matches(self, cve, product_name, version):
        """
        Verificar si la versión del servicio está afectada por el CVE

        Args:
            cve: Datos del CVE
            product_name: Nombre del producto
            version: Versión del servicio

        Returns:
            True si coincide (o no se puede determinar), False si definitivamente no coincide
        """
        # Por ahora, retornar True (match optimista)
        # Implementar lógica CPE matching en el futuro
        return True

    def _cvss2_to_severity(self, score):
        """
        Convertir CVSS v2 score a severidad

        Args:
            score: Score CVSS v2 (0-10)

        Returns:
            Severidad (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'

    def format_results_summary(self, results):
        """
        Formatear resumen de resultados

        Args:
            results: Resultados del análisis

        Returns:
            String con resumen formateado
        """
        if not results or results.get('total_cves', 0) == 0:
            return "No se encontraron vulnerabilidades conocidas"

        summary = []
        summary.append(f"\n{'='*60}")
        summary.append(f"VULNERABILITY MATCHER - Resumen")
        summary.append(f"{'='*60}")
        summary.append(f"Total CVEs encontrados: {results['total_cves']}")
        summary.append(f"\nPor Severidad:")

        by_sev = results.get('by_severity', {})
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_sev.get(sev, 0)
            if count > 0:
                summary.append(f"  {sev}: {count}")

        summary.append(f"\nServicios afectados: {len(results.get('services', []))}")

        for service in results.get('services', []):
            summary.append(f"\n{service['name']} {service.get('version', '')}")
            summary.append(f"  CVEs: {service['cve_count']}")

            # Mostrar top 3 CVEs más críticos
            cves_sorted = sorted(
                service['cves'],
                key=lambda x: x.get('cvss_score', 0),
                reverse=True
            )

            for cve in cves_sorted[:3]:
                summary.append(f"    - {cve['id']} ({cve['severity']}) CVSS: {cve['cvss_score']}")
                summary.append(f"      {cve['description'][:100]}...")

        return '\n'.join(summary)
