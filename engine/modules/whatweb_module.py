#!/usr/bin/env python3
"""
FAROSINT WhatWeb Module
Identificación de tecnologías web
"""

import json
import tempfile
from .base_module import BaseModule

class WhatWebModule(BaseModule):
    """Módulo para WhatWeb - identificación de tecnologías web"""

    def __init__(self, timeout=600, cache_manager=None):
        super().__init__("WhatWeb", timeout, cache_manager)

    def run(self, target, **kwargs):
        """
        Ejecutar WhatWeb para identificar tecnologías

        Args:
            target: URL o lista de URLs
            **kwargs: Parámetros adicionales
                - aggression: Nivel de agresión 1-4 (default: 3)
                - follow_redirect: Seguir redirects (default: True)

        Returns:
            Dict con tecnologías identificadas por URL
        """
        # Normalizar target a lista
        if isinstance(target, str):
            urls = [target]
        else:
            urls = target

        self.log(f"Iniciando identificación de tecnologías para {len(urls)} URLs")

        # Verificar caché
        params = {'aggression': kwargs.get('aggression', 3)}
        cache_key = ','.join(sorted(urls))
        cached_result = self.check_cache(cache_key, params)

        if cached_result:
            self.log("Usando resultado cacheado")
            return cached_result

        # Crear archivo temporal con URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for url in urls:
                f.write(url + '\n')
            url_file = f.name

        try:
            # Construir comando
            whatweb_path = self.get_tool_path('whatweb')

            cmd = [
                whatweb_path,
                '-i', url_file,
                '--log-json=-',  # Output JSON a stdout
                '-a', str(params['aggression']),
                '--color=never'
            ]

            if not kwargs.get('follow_redirect', True):
                cmd.append('--no-redirect')

            self.log(f"Ejecutando: {' '.join(cmd)}")
            stdout, stderr, returncode = self.execute_command(cmd)

            # Parsear resultados JSON
            results = self._parse_whatweb_json(stdout)

            self.log(f"Identificación completada: {len(results['urls'])} URLs analizadas")

            # Actualizar caché
            self.update_cache(cache_key, results, params)

            return results

        except TimeoutError as e:
            self.log(f"Timeout: {str(e)}", "WARNING")
            return {'urls': []}

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            return {'urls': []}

        finally:
            import os
            if os.path.exists(url_file):
                os.unlink(url_file)

    def _parse_whatweb_json(self, json_output):
        """
        Parsear JSON de WhatWeb

        Args:
            json_output: Output JSON de WhatWeb

        Returns:
            Dict con URLs y tecnologías identificadas
        """
        results = {'urls': []}

        try:
            # WhatWeb devuelve un JSON por línea
            for line in json_output.strip().split('\n'):
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)

                    url = data.get('target', '')
                    http_status = data.get('http_status', 0)

                    # Extraer plugins (tecnologías detectadas)
                    technologies = []
                    plugins = data.get('plugins', {})

                    for plugin_name, plugin_data in plugins.items():
                        # Normalizar plugin_data (puede ser dict o list)
                        if isinstance(plugin_data, dict):
                            tech_info = self._extract_tech_info(plugin_name, plugin_data)
                            if tech_info:
                                technologies.append(tech_info)
                        elif isinstance(plugin_data, list):
                            for item in plugin_data:
                                tech_info = self._extract_tech_info(plugin_name, item)
                                if tech_info:
                                    technologies.append(tech_info)

                    results['urls'].append({
                        'url': url,
                        'status': http_status,
                        'technologies': technologies
                    })

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    self.log(f"Error parseando línea JSON: {e}", "WARNING")
                    continue

        except Exception as e:
            self.log(f"Error parseando output JSON: {str(e)}", "ERROR")

        return results

    def _extract_tech_info(self, plugin_name, plugin_data):
        """
        Extraer información de tecnología desde plugin data

        Args:
            plugin_name: Nombre del plugin (tecnología)
            plugin_data: Datos del plugin

        Returns:
            Dict con información de tecnología o None
        """
        try:
            tech = {
                'name': plugin_name,
                'category': self._categorize_technology(plugin_name)
            }

            # Extraer versiones si existen
            if isinstance(plugin_data, dict):
                version = plugin_data.get('version', [])
                if version:
                    tech['version'] = version if isinstance(version, list) else [version]

                # Extraer string (puede contener info útil)
                string = plugin_data.get('string', [])
                if string:
                    tech['details'] = string if isinstance(string, list) else [string]

            return tech

        except Exception as e:
            self.log(f"Error extrayendo tech info para {plugin_name}: {e}", "WARNING")
            return None

    def _categorize_technology(self, tech_name):
        """
        Categorizar tecnología según su nombre

        Args:
            tech_name: Nombre de la tecnología

        Returns:
            Categoría
        """
        tech_lower = tech_name.lower()

        # Servidores web
        if any(x in tech_lower for x in ['nginx', 'apache', 'iis', 'lighttpd', 'tomcat', 'jetty']):
            return 'Web Server'

        # Lenguajes/Frameworks
        if any(x in tech_lower for x in ['php', 'python', 'ruby', 'java', 'node', 'asp', 'jsp']):
            return 'Language/Framework'

        # CMS
        if any(x in tech_lower for x in ['wordpress', 'joomla', 'drupal', 'magento', 'shopify']):
            return 'CMS'

        # JavaScript Frameworks
        if any(x in tech_lower for x in ['react', 'vue', 'angular', 'jquery', 'bootstrap']):
            return 'JavaScript Framework'

        # CDN
        if any(x in tech_lower for x in ['cloudflare', 'akamai', 'fastly', 'cloudfront']):
            return 'CDN'

        # Analytics
        if any(x in tech_lower for x in ['analytics', 'tag manager', 'tracking']):
            return 'Analytics'

        # Security
        if any(x in tech_lower for x in ['waf', 'firewall', 'security']):
            return 'Security'

        return 'Other'

    def format_results_summary(self, results):
        """
        Formatear resumen de resultados para visualización

        Args:
            results: Resultados de WhatWeb

        Returns:
            String con resumen formateado
        """
        if not results or 'urls' not in results:
            return "No se identificaron tecnologías"

        summary = []

        for url_data in results['urls']:
            url = url_data['url']
            technologies = url_data.get('technologies', [])

            summary.append(f"\n{url} ({url_data.get('status', 'N/A')})")

            # Agrupar por categoría
            categories = {}
            for tech in technologies:
                cat = tech.get('category', 'Other')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(tech)

            for category, techs in sorted(categories.items()):
                summary.append(f"  [{category}]")
                for tech in techs:
                    name = tech['name']
                    version = ', '.join(tech.get('version', [])) if 'version' in tech else ''
                    if version:
                        summary.append(f"    - {name} {version}")
                    else:
                        summary.append(f"    - {name}")

        return '\n'.join(summary)
