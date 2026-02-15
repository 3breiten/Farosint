#!/usr/bin/env python3
"""
FAROSINT Rustscan Module
Escaneo rápido de puertos para alimentar a Nmap
"""

import json
import tempfile
from pathlib import Path
from .base_module import BaseModule

class RustscanModule(BaseModule):
    """Módulo para Rustscan - escaneo rápido de puertos"""

    def __init__(self, timeout=300, cache_manager=None):
        super().__init__("Rustscan", timeout, cache_manager)

        # Agregar rustscan al mapeo de herramientas
        rustscan_path = Path.home() / 'FAROSINT' / 'tools' / 'rustscan'
        if rustscan_path.exists():
            self.tool_paths['rustscan'] = str(rustscan_path)

    def run(self, target, **kwargs):
        """
        Ejecutar Rustscan para descubrir puertos rápidamente

        Args:
            target: IP o hostname
            **kwargs: Parámetros adicionales
                - batch_size: Tamaño del lote paralelo (default: 4500)
                - ulimit: Límite de archivos abiertos (default: 5000)
                - timeout: Timeout por puerto en ms (default: 1500)

        Returns:
            Dict con puertos abiertos agrupados por host
        """
        self.log(f"Iniciando escaneo rápido de puertos: {target}")

        # Verificar caché
        params = {
            'batch_size': kwargs.get('batch_size', 4500),
            'timeout': kwargs.get('timeout', 1500)
        }
        cached_result = self.check_cache(target, params)

        if cached_result:
            self.log("Usando resultado cacheado")
            return cached_result

        try:
            # Construir comando
            rustscan_path = self.get_tool_path('rustscan')

            cmd = [
                rustscan_path,
                '-a', target,
                '--batch-size', str(params['batch_size']),
                '--timeout', str(params['timeout']),
                '--ulimit', str(kwargs.get('ulimit', 5000)),
                '--greppable',  # Output formato parseable
                '--no-nmap'     # Solo descubrimiento, sin ejecutar Nmap
            ]

            self.log(f"Ejecutando: {' '.join(cmd)}")
            stdout, stderr, returncode = self.execute_command(cmd)

            # Parsear resultados
            results = self._parse_rustscan_output(stdout, target)

            total_ports = sum(len(host['ports']) for host in results['hosts'])
            self.log(f"Escaneo completado: {total_ports} puertos abiertos")

            # Actualizar caché
            self.update_cache(target, results, params)

            return results

        except TimeoutError as e:
            self.log(f"Timeout: {str(e)}", "WARNING")
            return {'hosts': []}

        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            return {'hosts': []}

    def _parse_rustscan_output(self, output, target):
        """
        Parsear output de Rustscan en formato greppable

        Args:
            output: Output del comando rustscan
            target: Target escaneado

        Returns:
            Dict con hosts y puertos abiertos
        """
        ports = []

        try:
            # Rustscan en modo greppable devuelve líneas como:
            # Open 192.168.1.1:80
            # Open 192.168.1.1:443
            for line in output.strip().split('\n'):
                line = line.strip()

                if not line or not line.startswith('Open'):
                    continue

                # Parsear "Open IP:PORT"
                try:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_port = parts[1]
                        if ':' in ip_port:
                            ip, port = ip_port.rsplit(':', 1)
                            ports.append(int(port))
                except (ValueError, IndexError):
                    continue

            # Remover duplicados y ordenar
            ports = sorted(set(ports))

            # Construir resultado
            if ports:
                return {
                    'hosts': [{
                        'ip': target,
                        'ports': ports,
                        'total': len(ports)
                    }]
                }
            else:
                return {'hosts': []}

        except Exception as e:
            self.log(f"Error parseando output: {str(e)}", "ERROR")
            return {'hosts': []}

    def get_port_list_string(self, results):
        """
        Convertir resultados a string de puertos para Nmap

        Args:
            results: Resultados de rustscan

        Returns:
            String con puertos separados por comas (ej: "80,443,8080")
        """
        try:
            if not results or 'hosts' not in results or not results['hosts']:
                return ""

            all_ports = []
            for host in results['hosts']:
                all_ports.extend(host.get('ports', []))

            # Remover duplicados y ordenar
            unique_ports = sorted(set(all_ports))

            # Convertir a string
            return ','.join(map(str, unique_ports))

        except Exception as e:
            self.log(f"Error generando lista de puertos: {str(e)}", "ERROR")
            return ""
