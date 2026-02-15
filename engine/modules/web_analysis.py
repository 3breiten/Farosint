#!/usr/bin/env python3
"""
FAROSINT - Módulo de Análisis Web
Verifica URLs activas y detecta tecnologías
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict
import yaml

logger = logging.getLogger(__name__)

class WebAnalysisModule:
    """Módulo de análisis web"""
    
    def __init__(self, config_path: str = None):
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {'timeouts': {'httpx': 600, 'whatweb': 900}}
        
        self.timeout = self.config.get('timeouts', {})
        self.logger = logging.getLogger(__name__)
    
    def run_httpx(self, input_file: str, output_file: str) -> Dict:
        """Ejecuta Httpx para verificar URLs activas"""
        self.logger.info(f"[HTTPX] Verificando URLs desde: {input_file}")
        
        cmd = [
            'httpx',
            '-l', input_file,
            '-status-code',
            '-title',
            '-tech-detect',
            '-follow-redirects',
            '-o', output_file,
            '-silent'
        ]
        
        try:
            subprocess.run(cmd, timeout=self.timeout.get('httpx', 600))
            
            urls = []
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"[HTTPX] URLs activas: {len(urls)}")
            return {'success': True, 'urls': urls, 'count': len(urls)}
        except Exception as e:
            self.logger.error(f"[HTTPX] Error: {e}")
            return {'success': False, 'error': str(e), 'urls': []}
    
    def run_whatweb(self, url: str) -> Dict:
        """Ejecuta WhatWeb para identificar tecnologías"""
        self.logger.info(f"[WHATWEB] Analizando: {url}")
        
        cmd = ['whatweb', url, '--log-json=/dev/stdout', '-q']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.stdout:
                data = json.loads(result.stdout)
                return {'success': True, 'technologies': data}
            return {'success': False, 'technologies': {}}
        except Exception as e:
            self.logger.error(f"[WHATWEB] Error: {e}")
            return {'success': False, 'error': str(e), 'technologies': {}}
    
    def analyze_urls(self, urls: List[str]) -> Dict:
        """Analiza múltiples URLs"""
        results = []
        
        for url in urls[:10]:  # Limitar a 10 para no saturar
            tech_data = self.run_whatweb(url)
            if tech_data['success']:
                results.append({'url': url, 'data': tech_data})
        
        return {'analyzed': len(results), 'results': results}


def verify_alive_urls(subdomains_file: str, output_dir: str, config_path: str = None) -> Dict:
    """Función principal de verificación de URLs"""
    module = WebAnalysisModule(config_path)
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    output_file = output_path / 'alive_urls.txt'
    result = module.run_httpx(subdomains_file, str(output_file))
    
    result['output_file'] = str(output_file)
    return result
