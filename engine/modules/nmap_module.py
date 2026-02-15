#!/usr/bin/env python3
"""
FAROSINT Nmap Module
Escaneo de puertos y detección de servicios
"""

import os
import xml.etree.ElementTree as ET
import tempfile
import json
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from .base_module import BaseModule

class NmapModule(BaseModule):
    """Módulo para Nmap"""

    def __init__(self, timeout=1800, cache_manager=None):
        super().__init__("Nmap", timeout, cache_manager)
        self.ports_db_file = self.engine_dir / "data" / "ports_database.json"
        self.ports_db_file.parent.mkdir(parents=True, exist_ok=True)

        # Actualizar base de datos si es necesario
        self._update_ports_database_if_needed()

        # Cargar base de datos
        self.port_services = self._load_services_database()

    def _update_ports_database_if_needed(self):
        """
        Actualizar base de datos de puertos si tiene más de 24 horas
        """
        # Verificar si el archivo existe y cuándo fue actualizado
        if self.ports_db_file.exists():
            file_age = datetime.now() - datetime.fromtimestamp(self.ports_db_file.stat().st_mtime)
            if file_age < timedelta(days=1):
                # Base de datos actualizada recientemente
                return

        # Descargar nueva base de datos
        self.log("Actualizando base de datos de puertos desde IANA...")
        try:
            self._download_ports_database()
            self.log("Base de datos de puertos actualizada exitosamente")
        except Exception as e:
            self.log(f"Error actualizando base de datos de puertos: {str(e)}", "WARNING")

    def _download_ports_database(self):
        """
        Descargar base de datos de puertos oficial desde IANA
        URL: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
        """
        url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

        try:
            self.log(f"Descargando desde: {url}")
            with urllib.request.urlopen(url, timeout=30) as response:
                csv_data = response.read().decode('utf-8')

            # Parsear CSV y construir base de datos
            services = {}
            lines = csv_data.split('\n')

            # Saltar header
            for line in lines[1:]:
                if not line.strip():
                    continue

                parts = line.split(',')
                if len(parts) < 4:
                    continue

                service_name = parts[0].strip().strip('"')
                port_number = parts[1].strip().strip('"')
                transport_protocol = parts[2].strip().strip('"').lower()
                description = parts[3].strip().strip('"') if len(parts) > 3 else ''

                # Ignorar rangos de puertos y entradas sin puerto
                if not port_number or '-' in port_number or not port_number.isdigit():
                    continue

                try:
                    port = int(port_number)
                    if not service_name:
                        continue

                    # Crear key (port, protocol)
                    if transport_protocol in ['tcp', 'udp', 'sctp', 'dccp']:
                        key = f"{port}/{transport_protocol}"
                        if key not in services:
                            services[key] = {
                                'name': service_name,
                                'description': description
                            }
                except ValueError:
                    continue

            # Guardar en archivo JSON
            with open(self.ports_db_file, 'w') as f:
                json.dump({
                    'last_updated': datetime.now().isoformat(),
                    'source': url,
                    'total_entries': len(services),
                    'services': services
                }, f, indent=2)

            self.log(f"Base de datos guardada: {len(services)} entradas")

        except Exception as e:
            self.log(f"Error descargando base de datos: {str(e)}", "ERROR")
            raise

    def _load_services_database(self):
        """
        Cargar base de datos de servicios (primero JSON actualizado, fallback a /etc/services)

        Returns:
            Dict con mappings {(port, protocol): service_name}
        """
        services = {}

        # Intentar cargar desde JSON actualizado primero
        if self.ports_db_file.exists():
            try:
                with open(self.ports_db_file, 'r') as f:
                    data = json.load(f)

                # Convertir a formato interno
                for port_proto, service_data in data.get('services', {}).items():
                    # port_proto es "80/tcp", separar
                    port_str, proto = port_proto.split('/')
                    port = int(port_str)
                    key = (port, proto.lower())
                    services[key] = service_data['name']

                last_updated = data.get('last_updated', 'unknown')
                self.log(f"Cargados {len(services)} puertos desde base de datos IANA (actualizada: {last_updated[:10]})")
                return services

            except Exception as e:
                self.log(f"Error cargando JSON, usando fallback: {str(e)}", "WARNING")

        # Fallback: cargar desde /etc/services
        try:
            with open('/etc/services', 'r') as f:
                for line in f:
                    # Ignorar comentarios y líneas vacías
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Parsear línea: service_name port/proto [aliases] [# comment]
                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    service_name = parts[0]
                    port_proto = parts[1]

                    # Separar puerto y protocolo
                    if '/' not in port_proto:
                        continue

                    try:
                        port_str, protocol = port_proto.split('/')
                        port = int(port_str)

                        # Guardar mapping (port, protocol) -> service_name
                        key = (port, protocol.lower())
                        if key not in services:  # Mantener primera definición
                            services[key] = service_name
                    except (ValueError, IndexError):
                        continue

            self.log(f"Cargados {len(services)} puertos desde /etc/services (fallback)")
            return services

        except FileNotFoundError:
            self.log("Warning: No se pudo cargar base de datos de puertos", "WARNING")
            return {}
        except Exception as e:
            self.log(f"Error cargando base de datos: {str(e)}", "WARNING")
            return {}

    def run(self, target, **kwargs):
        """
        Ejecutar Nmap

        Args:
            target: IP, hostname o archivo con targets
            **kwargs: Parámetros adicionales
                - scan_type: 'quick', 'full', 'custom' (default: 'quick')
                - ports: Puertos a escanear (default: depende de scan_type)
                - service_detection: Detección de versiones (default: True)

        Returns:
            Dict con resultados del escaneo
        """
        scan_type = kwargs.get('scan_type', 'quick')

        self.log(f"Iniciando escaneo Nmap ({scan_type}) de: {target}")

        # Verificar caché - DESHABILITADO para escaneos LAN para evitar resultados vacíos
        is_lan_target = self._is_lan_target(target)
        params = {'scan_type': scan_type}
        if not is_lan_target:
            cached_result = self.check_cache(target, params)
            if cached_result:
                self.log("Usando resultado cacheado")
                return cached_result
        else:
            self.log("Escaneo LAN detectado - cache deshabilitado para resultados frescos")

        # Crear archivo temporal para XML
        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.xml')
        output_file.close()

        try:
            # Construir comando base con ruta absoluta
            nmap_path = self.get_tool_path('nmap')
            cmd = [nmap_path, target, '-oX', output_file.name]

            # CRÍTICO: Agregar -Pn para skip host discovery (esencial para LANs con firewall)
            cmd.append('-Pn')

            # Configurar según tipo de escaneo
            if scan_type == 'quick':
                cmd.extend(['--top-ports', '100', '-T4'])
            elif scan_type == 'full':
                cmd.extend(['--top-ports', '1000', '-T4'])
            elif scan_type == 'custom' and 'ports' in kwargs:
                cmd.extend(['-p', str(kwargs['ports'])])

            # Detección de servicios
            if kwargs.get('service_detection', True):
                cmd.extend(['-sV', '-sC'])

            # Para targets LAN, agregar scripts adicionales de valor
            if is_lan_target:
                cmd.extend([
                    '--script', 'smb-os-discovery,smb-enum-shares,smb-enum-users,nbstat,smb-vuln-ms17-010,smb-vuln-ms08-067,vulners',
                    '--script-timeout', '30',
                ])
            
            # Ejecutar
            self.log(f"Ejecutando: {' '.join(cmd)}")
            stdout, stderr, returncode = self.execute_command(cmd)
            
            # Parsear XML
            results = self._parse_nmap_xml(output_file.name)
            
            self.log(f"Escaneo completado: {len(results.get('hosts', []))} hosts")
            
            # Actualizar caché
            self.update_cache(target, results, params)
            
            return results
            
        except TimeoutError as e:
            self.log(f"Timeout: {str(e)}", "WARNING")
            # Intentar parsear resultados parciales
            if os.path.exists(output_file.name):
                results = self._parse_nmap_xml(output_file.name)
                self.log("Resultados parciales obtenidos")
                return results
            return {'hosts': []}
        
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            return {'hosts': []}
        
        finally:
            if os.path.exists(output_file.name):
                os.unlink(output_file.name)
    
    def _is_lan_target(self, target):
        """Detectar si el target es una IP/CIDR (escaneo LAN)"""
        import ipaddress
        target = target.strip()
        # CIDR
        if '/' in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                pass
        # IP simple
        try:
            ip = ipaddress.ip_address(target)
            return ip.is_private
        except ValueError:
            pass
        return False

    def _parse_nmap_xml(self, xml_file):
        """
        Parsear XML de Nmap
        
        Args:
            xml_file: Archivo XML de Nmap
            
        Returns:
            Dict con resultados parseados
        """
        if not os.path.exists(xml_file):
            return {'hosts': []}
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            hosts = []
            
            for host in root.findall('host'):
                # Obtener IP
                address = host.find('address')
                if address is None:
                    continue
                
                ip = address.get('addr')
                
                # Obtener hostname
                hostnames = []
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall('hostname'):
                        name = hostname.get('name')
                        if name:
                            hostnames.append(name)
                
                # Obtener puertos
                ports = []
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        portid = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state = port.find('state')
                        state_val = state.get('state') if state is not None else 'unknown'
                        
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else 'unknown'
                        service_product = service.get('product') if service is not None else ''
                        service_version = service.get('version') if service is not None else ''
                        service_tunnel = service.get('tunnel') if service is not None else ''

                        # Enriquecer servicios desconocidos con base de datos de puertos
                        port_key = (int(portid), protocol.lower())
                        std_service = self.port_services.get(port_key, None)

                        # Si el servicio es tcpwrapped, unknown o vacío, intentar enriquecer
                        if service_name in ['tcpwrapped', 'unknown', ''] or not service_name:
                            if std_service:
                                # Usar el servicio estándar de la base de datos
                                service_name = std_service
                            else:
                                # Si no está en la base de datos, marcar como desconocido
                                service_name = 'desconocido'

                        # Mejorar detección de HTTPS
                        # Si el puerto es típicamente HTTPS pero Nmap detectó HTTP, corregir
                        if int(portid) in [443, 8443, 8444, 9443] and service_name == 'http':
                            service_name = 'https'

                        # Si hay tunnel SSL/TLS, es HTTPS
                        if service_tunnel in ['ssl', 'tls'] and service_name == 'http':
                            service_name = 'https'

                        ports.append({
                            'port': int(portid),
                            'protocol': protocol,
                            'state': state_val,
                            'service': service_name,
                            'product': service_product,
                            'version': service_version
                        })
                
                # OS Detection
                os_info = {}
                os_elem = host.find('os')
                if os_elem is not None:
                    for osmatch in os_elem.findall('osmatch'):
                        os_info = {
                            'name': osmatch.get('name', ''),
                            'accuracy': osmatch.get('accuracy', ''),
                            'osfamily': '',
                            'osgen': ''
                        }
                        osclass = osmatch.find('osclass')
                        if osclass is not None:
                            os_info['osfamily'] = osclass.get('osfamily', '')
                            os_info['osgen'] = osclass.get('osgen', '')
                        break  # Solo el primer match (mejor)

                # Host Scripts (SMB, NetBIOS, etc.)
                host_scripts = []
                hostscript_elem = host.find('hostscript')
                if hostscript_elem is not None:
                    for script in hostscript_elem.findall('script'):
                        script_data = {
                            'id': script.get('id', ''),
                            'output': script.get('output', '')
                        }
                        host_scripts.append(script_data)

                hosts.append({
                    'ip': ip,
                    'hostnames': hostnames,
                    'ports': ports,
                    'os': os_info,
                    'scripts': host_scripts
                })

            # Extraer vulnerabilidades de scripts NSE
            nse_vulns = self._extract_nse_vulnerabilities(hosts)

            return {'hosts': hosts, 'nse_vulnerabilities': nse_vulns}

        except Exception as e:
            self.log(f"Error parseando XML: {str(e)}", "ERROR")
            return {'hosts': []}

    def _extract_nse_vulnerabilities(self, hosts):
        """
        Extraer vulnerabilidades detectadas por scripts NSE de Nmap

        Returns:
            Lista de dicts con vulnerabilidades encontradas
        """
        import re
        vulns = []

        for host in hosts:
            ip = host.get('ip', '')

            for script in host.get('scripts', []):
                script_id = script.get('id', '')
                output = script.get('output', '')

                # Detectar scripts de vulnerabilidad (smb-vuln-*)
                if 'vuln' in script_id.lower() and 'VULNERABLE' in output:
                    # Extraer CVE
                    cve_match = re.search(r'CVE[:\-](\d{4}[\-]\d+)', output)
                    cve = cve_match.group(0).replace(':', '-') if cve_match else None

                    # Extraer nombre legible
                    name_match = re.search(r'(.*?)(?:\n|$)', output.strip())
                    vuln_name = name_match.group(1).strip() if name_match else script_id

                    # Determinar severidad según el script
                    severity = 'high'
                    cvss = 8.0
                    if 'ms17-010' in script_id:
                        severity = 'critical'
                        cvss = 9.8
                        vuln_name = 'MS17-010 EternalBlue SMBv1 RCE'
                    elif 'ms08-067' in script_id:
                        severity = 'critical'
                        cvss = 10.0
                        vuln_name = 'MS08-067 NetAPI RCE'

                    vulns.append({
                        'name': vuln_name,
                        'severity': severity,
                        'host': ip,
                        'matched_at': ip,
                        'cve': cve,
                        'cvss_score': cvss,
                        'template': f'nmap-{script_id}',
                        'description': output.strip(),
                        'tags': ['nmap', 'nse', script_id],
                        'references': {},
                        'remediation': {'steps': ['Aplicar parches de seguridad de Microsoft', 'Deshabilitar SMBv1 si no es necesario']}
                    })

                # Scripts vulners (busca CVEs en versiones de servicio)
                elif script_id == 'vulners' and 'CVE-' in output:
                    for line in output.split('\n'):
                        cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
                        if cve_match:
                            cve_id = cve_match.group(1)
                            cvss_match = re.search(r'(\d+\.\d+)', line)
                            cvss_score = float(cvss_match.group(1)) if cvss_match else 5.0

                            if cvss_score >= 7.0:
                                sev = 'high'
                            elif cvss_score >= 4.0:
                                sev = 'medium'
                            else:
                                sev = 'low'
                            if cvss_score >= 9.0:
                                sev = 'critical'

                            vulns.append({
                                'name': f'{cve_id} (Nmap vulners)',
                                'severity': sev,
                                'host': ip,
                                'matched_at': ip,
                                'cve': cve_id,
                                'cvss_score': cvss_score,
                                'template': 'nmap-vulners',
                                'description': line.strip(),
                                'tags': ['nmap', 'vulners'],
                                'references': {},
                                'remediation': {'steps': ['Actualizar el servicio a la última versión']}
                            })

        self.log(f"Vulnerabilidades NSE extraídas: {len(vulns)}")
        return vulns
