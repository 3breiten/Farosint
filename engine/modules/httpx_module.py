#!/usr/bin/env python3
"""
FAROSINT Httpx Module
Verificación de servicios HTTP/HTTPS activos
"""

import os
import json
import tempfile
from .base_module import BaseModule

class HttpxModule(BaseModule):
    """Módulo para Httpx"""
    
    def __init__(self, timeout=600, cache_manager=None):
        super().__init__("Httpx", timeout, cache_manager)
    
    def run(self, hosts, **kwargs):
        """
        Ejecutar Httpx
        
        Args:
            hosts: Lista de hosts o archivo con hosts
            **kwargs: Parámetros adicionales
                - threads: Número de threads (default: 50)
                - timeout_per_host: Timeout por host en segundos (default: 10)
                
        Returns:
            Lista de URLs activas con metadatos
        """
        self.log(f"Verificando {len(hosts) if isinstance(hosts, list) else '?'} hosts")
        
        # Preparar lista de hosts
        if isinstance(hosts, list):
            hosts_list = hosts
        else:
            # Asumir que es un archivo
            with open(hosts, 'r') as f:
                hosts_list = [line.strip() for line in f if line.strip()]
        
        if not hosts_list:
            self.log("Lista de hosts vacía", "WARNING")
            return []
        
        # Crear archivos temporales
        input_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        
        try:
            # Escribir hosts en archivo
            input_file.write('\n'.join(hosts_list))
            input_file.close()
            output_file.close()
            
            # Construir comando con ruta absoluta
            httpx_path = self.get_tool_path('httpx')
            cmd = [
                httpx_path,
                '-l', input_file.name,
                '-title',
                '-tech-detect',
                '-status-code',
                '-content-length',
                '-follow-redirects',
                '-timeout', str(kwargs.get('timeout_per_host', 30)),
                '-retries', str(kwargs.get('retries', 2)),
                '-threads', str(kwargs.get('threads', 20)),
                '-json',
                '-o', output_file.name,
                '-silent'
            ]
            
            # Ejecutar
            self.log(f"Ejecutando: {' '.join(cmd)}")
            stdout, stderr, returncode = self.execute_command(cmd)
            
            # Leer resultados JSON
            results = []
            if os.path.exists(output_file.name):
                with open(output_file.name, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            
            self.log(f"Encontradas {len(results)} URLs activas de {len(hosts_list)} hosts")
            
            return results
            
        except TimeoutError as e:
            self.log(f"Timeout: {str(e)}", "WARNING")
            # Intentar leer resultados parciales
            results = []
            if os.path.exists(output_file.name):
                with open(output_file.name, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            self.log(f"Resultados parciales: {len(results)} URLs")
            return results
        
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            return []
        
        finally:
            # Limpiar archivos temporales
            if os.path.exists(input_file.name):
                os.unlink(input_file.name)
            if os.path.exists(output_file.name):
                os.unlink(output_file.name)
