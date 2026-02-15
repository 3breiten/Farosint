#!/usr/bin/env python3
"""
FAROSINT - Módulo de Escaneo de Puertos
Detección de servicios con Nmap
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict
import yaml
import re

logger = logging.getLogger(__name__)

class PortScanModule:
    """Módulo de escaneo de puertos"""
    
    def __init__(self, config_path: str = None):
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {'timeouts': {'nmap_quick': 300, 'nmap_full': 1800}}
        
        self.timeout = self.config.get('timeouts', {})
        self.logger = logging.getLogger(__name__)
    
    def run_nmap_quick(self, target: str, output_file: str) -> Dict:
        """Escaneo rápido (top 100 puertos)"""
        self.logger.info(f"[NMAP QUICK] Escaneando: {target}")
        
        cmd = ['nmap', '-F', target, '-oN', output_file, '-Pn', '--open']
        
        try:
            subprocess.run(cmd, timeout=self.timeout.get('nmap_quick', 300))
            
            ports = self._parse_nmap_output(output_file)
            
            self.logger.info(f"[NMAP QUICK] Puertos encontrados: {len(ports)}")
            return {'success': True, 'ports': ports, 'count': len(ports)}
        except Exception as e:
            self.logger.error(f"[NMAP QUICK] Error: {e}")
            return {'success': False, 'error': str(e), 'ports': {}}
    
    def run_nmap_full(self, target: str, output_file: str) -> Dict:
        """Escaneo completo (top 1000 puertos)"""
        self.logger.info(f"[NMAP FULL] Escaneando: {target}")
        
        cmd = ['nmap', '-p', '1-1000', target, '-oN', output_file, '-Pn', '--open']
        
        try:
            subprocess.run(cmd, timeout=self.timeout.get('nmap_full', 1800))
            
            ports = self._parse_nmap_output(output_file)
            
            self.logger.info(f"[NMAP FULL] Puertos encontrados: {len(ports)}")
            return {'success': True, 'ports': ports, 'count': len(ports)}
        except Exception as e:
            self.logger.error(f"[NMAP FULL] Error: {e}")
            return {'success': False, 'error': str(e), 'ports': {}}
    
    def _parse_nmap_output(self, output_file: str) -> Dict:
        """Parsea salida de Nmap"""
        ports = {}
        
        if not Path(output_file).exists():
            return ports
        
        with open(output_file, 'r') as f:
            for line in f:
                # Buscar líneas con puertos abiertos: 80/tcp   open  http
                match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', line)
                if match:
                    port_num = match.group(1)
                    protocol = match.group(2)
                    service = match.group(3)
                    ports[f"{port_num}/{protocol}"] = service
        
        return ports


def scan_ports(target: str, output_dir: str, scan_type: str = 'quick', config_path: str = None) -> Dict:
    """Función principal de escaneo de puertos"""
    module = PortScanModule(config_path)
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    output_file = output_path / f'nmap_{scan_type}.txt'
    
    if scan_type == 'full':
        result = module.run_nmap_full(target, str(output_file))
    else:
        result = module.run_nmap_quick(target, str(output_file))
    
    result['output_file'] = str(output_file)
    return result
