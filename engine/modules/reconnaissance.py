#!/usr/bin/env python3
"""
FAROSINT - Módulo de Reconocimiento
Enumeración de subdominios y assets
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict
import yaml
import re

logger = logging.getLogger(__name__)

class ReconnaissanceModule:
    """Módulo de reconocimiento OSINT"""
    
    def __init__(self, config_path: str = None):
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = self._default_config()
        
        self.timeout = self.config.get('timeouts', {})
        self.logger = logging.getLogger(__name__)
    
    def _default_config(self) -> Dict:
        return {
            'timeouts': {'subfinder': 300, 'amass': 1800, 'theharvester': 900},
            'limits': {'max_subdomains': 500},
            'scope': {
                'exclude_patterns': [r'^[0-9]+\..*', r'^-.*', r'.*\.cdn\..*'],
                'priority_keywords': ['admin', 'api', 'dev', 'test', 'staging']
            }
        }
    
    def run_subfinder(self, domain: str, output_file: str) -> Dict:
        """Ejecuta Subfinder"""
        self.logger.info(f"[SUBFINDER] Escaneando: {domain}")
        
        cmd = ['subfinder', '-d', domain, '-all', '-o', output_file, '-silent']
        
        try:
            subprocess.run(cmd, timeout=self.timeout.get('subfinder', 300), check=True)
            
            subdomains = []
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"[SUBFINDER] Encontrados: {len(subdomains)}")
            return {'success': True, 'tool': 'subfinder', 'subdomains': subdomains, 'count': len(subdomains)}
        except Exception as e:
            self.logger.error(f"[SUBFINDER] Error: {e}")
            return {'success': False, 'error': str(e), 'subdomains': []}
    
    def run_amass(self, domain: str, output_file: str) -> Dict:
        """Ejecuta Amass"""
        self.logger.info(f"[AMASS] Escaneando: {domain}")
        
        cmd = ['amass', 'enum', '-d', domain, '-o', output_file, '-passive']
        
        try:
            subprocess.run(cmd, timeout=self.timeout.get('amass', 1800))
            
            subdomains = []
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"[AMASS] Encontrados: {len(subdomains)}")
            return {'success': True, 'tool': 'amass', 'subdomains': subdomains, 'count': len(subdomains)}
        except Exception as e:
            self.logger.error(f"[AMASS] Error: {e}")
            subdomains = []
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            return {'success': False, 'error': str(e), 'subdomains': subdomains}
    
    def combine_results(self, results: List[Dict]) -> Dict:
        """Combina resultados únicos"""
        all_subdomains = set()
        
        for result in results:
            if result.get('success'):
                subs = result.get('subdomains', [])
                if isinstance(subs, list):
                    all_subdomains.update(subs)
        
        filtered = self._filter_subdomains(list(all_subdomains))
        
        return {
            'subdomains': sorted(filtered),
            'total_subdomains': len(filtered)
        }
    
    def _filter_subdomains(self, subdomains: List[str]) -> List[str]:
        """Filtra subdominios según patrones"""
        exclude_patterns = self.config.get('scope', {}).get('exclude_patterns', [])
        
        filtered = []
        for sub in subdomains:
            excluded = False
            for pattern in exclude_patterns:
                if re.match(pattern, sub):
                    excluded = True
                    break
            if not excluded:
                filtered.append(sub)
        
        max_subs = self.config.get('limits', {}).get('max_subdomains', 500)
        return filtered[:max_subs]


def enumerate_subdomains(domain: str, output_dir: str, config_path: str = None) -> Dict:
    """Función principal de enumeración"""
    module = ReconnaissanceModule(config_path)
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    results = []
    
    # Subfinder
    subfinder_out = output_path / 'subfinder.txt'
    results.append(module.run_subfinder(domain, str(subfinder_out)))
    
    # Amass
    amass_out = output_path / 'amass.txt'
    results.append(module.run_amass(domain, str(amass_out)))
    
    # Combinar
    combined = module.combine_results(results)
    
    # Guardar
    output_file = output_path / 'all_subdomains.txt'
    with open(output_file, 'w') as f:
        for sub in combined['subdomains']:
            f.write(f"{sub}\n")
    
    combined['output_file'] = str(output_file)
    return combined
