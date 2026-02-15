#!/usr/bin/env python3
"""
FAROSINT Vulnerability Matcher
Detecta CVEs automáticamente basándose en producto y versión
"""

import vulners
import time
from datetime import datetime
from pathlib import Path
import json

class VulnMatcher:
    """Matcher de vulnerabilidades usando Vulners API"""

    def __init__(self, api_key=None, cache_dir=None):
        """
        Inicializar VulnMatcher

        Args:
            api_key: API key de Vulners (opcional, usa clave pública si no se provee)
            cache_dir: Directorio para caché local
        """
        # Vulners funciona sin API key (modo público con rate limits)
        # o con API key para mayor throughput
        self.vulners_api = vulners.VulnersApi(api_key=api_key if api_key else "")

        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".farosint" / "vuln_matcher_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, software, version):
        """Obtener ruta de caché para software+version"""
        cache_key = f"{software}_{version}".replace('/', '_').replace(' ', '_')
        return self.cache_dir / f"{cache_key}.json"

    def _load_from_cache(self, software, version):
        """Cargar desde caché si existe y es válido (7 días)"""
        cache_path = self._get_cache_path(software, version)

        if not cache_path.exists():
            return None

        try:
            # Verificar antigüedad
            mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
            age = datetime.now() - mtime

            if age.days > 7:  # Cache expirado
                return None

            with open(cache_path, 'r') as f:
                return json.load(f)
        except:
            return None

    def _save_to_cache(self, software, version, data):
        """Guardar en caché"""
        try:
            cache_path = self._get_cache_path(software, version)
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error guardando caché: {e}")

    def find_vulnerabilities(self, service_name, product, version):
        """
        Buscar vulnerabilidades para un servicio específico

        Args:
            service_name: Nombre del servicio (http, ssh, ftp, etc.)
            product: Producto/software (Apache, OpenSSH, vsftpd, etc.)
            version: Versión del software

        Returns:
            Lista de vulnerabilidades encontradas
        """
        if not product or not version:
            return []

        # Verificar caché
        cached = self._load_from_cache(product, version)
        if cached is not None:
            return cached

        vulnerabilities = []

        try:
            # Construir query de búsqueda
            # Vulners espera formato: "software version"
            query = f"{product} {version}"

            # Buscar vulnerabilidades
            results = self.vulners_api.find_all(query)

            # Procesar resultados
            for vuln_type, vuln_list in results.items():
                for vuln in vuln_list:
                    try:
                        # Extraer información relevante
                        vuln_data = {
                            'cve': vuln.get('id', ''),
                            'title': vuln.get('title', ''),
                            'description': vuln.get('description', ''),
                            'cvss_score': vuln.get('cvss', {}).get('score', 0),
                            'cvss_vector': vuln.get('cvss', {}).get('vector', ''),
                            'published': vuln.get('published', ''),
                            'modified': vuln.get('modified', ''),
                            'references': vuln.get('references', []),
                            'source': 'Vulners',
                            'type': vuln_type,
                            'affected_software': f"{product} {version}"
                        }

                        # Solo incluir si tiene CVE ID válido y CVSS > 0
                        if vuln_data['cve'].startswith('CVE-') and vuln_data['cvss_score'] > 0:
                            vulnerabilities.append(vuln_data)

                    except Exception as e:
                        print(f"Error procesando vulnerabilidad: {e}")
                        continue

            # Ordenar por CVSS (mayor a menor)
            vulnerabilities.sort(key=lambda x: x['cvss_score'], reverse=True)

            # Limitar a top 20 vulnerabilidades más críticas
            vulnerabilities = vulnerabilities[:20]

            # Guardar en caché
            self._save_to_cache(product, version, vulnerabilities)

            return vulnerabilities

        except Exception as e:
            print(f"Error buscando vulnerabilidades para {product} {version}: {e}")
            return []

    def match_service_vulnerabilities(self, services_list):
        """
        Buscar vulnerabilidades para una lista de servicios

        Args:
            services_list: Lista de dicts con keys: service, product, version, port, ip

        Returns:
            Lista de vulnerabilidades encontradas con contexto de servicio
        """
        all_vulnerabilities = []

        for service in services_list:
            service_name = service.get('service', 'unknown')
            product = service.get('product', '')
            version = service.get('version', '')
            port = service.get('port', 0)
            ip = service.get('ip', '')

            # Normalizar nombres de productos comunes
            product = self._normalize_product_name(product, service_name)

            if not product or not version:
                continue

            # Buscar vulnerabilidades
            vulns = self.find_vulnerabilities(service_name, product, version)

            # Agregar contexto de servicio
            for vuln in vulns:
                vuln['port'] = port
                vuln['ip'] = ip
                vuln['service'] = service_name
                all_vulnerabilities.append(vuln)

            # Rate limiting para API pública (1 req/segundo)
            time.sleep(1.0)

        return all_vulnerabilities

    def _normalize_product_name(self, product, service_name):
        """
        Normalizar nombres de productos para mejor matching

        Args:
            product: Nombre del producto detectado
            service_name: Nombre del servicio

        Returns:
            Nombre normalizado
        """
        if not product:
            return ""

        # Mapeo de productos comunes
        product_map = {
            'Apache httpd': 'Apache',
            'nginx': 'nginx',
            'Microsoft IIS': 'IIS',
            'OpenSSH': 'OpenSSH',
            'ProFTPD': 'ProFTPD',
            'vsftpd': 'vsftpd',
            'MySQL': 'MySQL',
            'PostgreSQL': 'PostgreSQL',
            'MongoDB': 'MongoDB',
            'Redis': 'Redis',
            'Tomcat': 'Apache Tomcat',
            'Jetty': 'Jetty',
        }

        # Buscar en mapeo
        for key, value in product_map.items():
            if key.lower() in product.lower():
                return value

        # Si no hay mapeo, devolver el producto original limpio
        return product.strip()

    def enrich_nmap_results(self, nmap_results):
        """
        Enriquecer resultados de Nmap con vulnerabilidades automáticas

        Args:
            nmap_results: Dict con resultados de NmapModule

        Returns:
            Lista de vulnerabilidades detectadas
        """
        if not nmap_results or 'hosts' not in nmap_results:
            return []

        services_list = []

        # Extraer servicios de todos los hosts
        for host in nmap_results['hosts']:
            ip = host.get('ip', '')
            ports = host.get('ports', [])

            for port_info in ports:
                # Solo procesar puertos con producto y versión
                product = port_info.get('product', '')
                version = port_info.get('version', '')

                if product and version:
                    services_list.append({
                        'ip': ip,
                        'port': port_info.get('port', 0),
                        'service': port_info.get('service', 'unknown'),
                        'product': product,
                        'version': version
                    })

        # Buscar vulnerabilidades
        print(f"[VulnMatcher] Analizando {len(services_list)} servicios con versión...")
        vulnerabilities = self.match_service_vulnerabilities(services_list)
        print(f"[VulnMatcher] Encontradas {len(vulnerabilities)} vulnerabilidades")

        return vulnerabilities
