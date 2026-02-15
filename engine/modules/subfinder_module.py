#!/usr/bin/env python3
"""
FAROSINT Subfinder Module
Enumeración rápida de subdominios
"""

import os
from pathlib import Path
from .base_module import BaseModule

class SubfinderModule(BaseModule):
    """Módulo para Subfinder"""
    
    def __init__(self, timeout=300, cache_manager=None):
        super().__init__("Subfinder", timeout, cache_manager)
    
    def run(self, domain, **kwargs):
        """
        Ejecutar Subfinder
        
        Args:
            domain: Dominio objetivo
            **kwargs: Parámetros adicionales
                - recursive: Búsqueda recursiva (default: True)
                - all_sources: Usar todas las fuentes (default: True)
                - max_time: Tiempo máximo en minutos (default: 5)
            
        Returns:
            Lista de subdominios encontrados
        """
        self.log(f"Iniciando enumeración de subdominios para: {domain}")
        
        # Verificar caché
        params = {
            'recursive': kwargs.get('recursive', True),
            'all_sources': kwargs.get('all_sources', True)
        }
        
        cached_result = self.check_cache(domain, params)
        if cached_result:
            self.log(f"Usando resultado cacheado ({len(cached_result)} subdominios)")
            return cached_result
        
        # Crear archivo temporal para salida
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_output = f.name
        
        try:
            # Construir comando con ruta absoluta
            subfinder_path = self.get_tool_path('subfinder')
            cmd = [subfinder_path, '-d', domain, '-o', temp_output, '-silent']

            # CRÍTICO: Solo usar fuentes públicas confiables (no requieren API keys)
            # Usar -all causa colgado con APIs sin configurar
            public_sources = 'crtsh,hackertarget,bufferover,dnsdumpster,alienvault,waybackarchive'
            cmd.extend(['-sources', public_sources])

            if kwargs.get('recursive', True):
                cmd.append('-recursive')

            max_time = kwargs.get('max_time', 5)
            cmd.extend(['-max-time', str(max_time)])
            
            # Ejecutar
            self.log(f"Ejecutando: {' '.join(cmd)}")
            stdout, stderr, returncode = self.execute_command(cmd)
            
            # Leer resultados
            if os.path.exists(temp_output):
                with open(temp_output, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            else:
                subdomains = []
            
            self.log(f"Encontrados {len(subdomains)} subdominios")
            
            # Actualizar caché
            self.update_cache(domain, subdomains, params)
            
            return subdomains
            
        except TimeoutError as e:
            self.log(f"Timeout: {str(e)}", "WARNING")
            return []
        
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            return []
        
        finally:
            # Limpiar archivo temporal
            if os.path.exists(temp_output):
                os.unlink(temp_output)

# Test del módulo
if __name__ == "__main__":
    from ..core.cache_manager import CacheManager
    
    cache = CacheManager()
    subfinder = SubfinderModule(cache_manager=cache)
    
    results = subfinder.run("example.com")
    print(f"\nResultados: {results}")
