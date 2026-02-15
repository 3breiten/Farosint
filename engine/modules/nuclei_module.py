#!/usr/bin/env python3
"""
WRAPPER: Llama al nuevo módulo vulnerability_scan.py
Mantiene compatibilidad con orchestrator.py
"""
from pathlib import Path
import tempfile
import os
import sys

# Importar el módulo nuevo
sys.path.insert(0, str(Path(__file__).parent))
from vulnerability_scan import scan_vulnerabilities

class NucleiModule:
    """Wrapper para mantener compatibilidad con orchestrator"""
    
    def __init__(self, timeout=None, cache_manager=None, config=None):
        """
        Inicializar módulo
        
        Args:
            timeout: Timeout para Nuclei (ignorado, usa el del módulo nuevo)
            cache_manager: Cache manager (ignorado por ahora)
            config: Configuración adicional
        """
        self.timeout = timeout
        self.cache_manager = cache_manager
        self.config = config or {}
        print("[NucleiModule WRAPPER] Inicializado - usa vulnerability_scan.py")
    
    def run(self, urls):
        """
        Ejecuta escaneo de vulnerabilidades
        
        Args:
            urls: Lista de URLs o string única
        
        Returns:
            Lista de vulnerabilidades (para compatibilidad con orchestrator)
        """
        # Convertir a lista si es string
        if isinstance(urls, str):
            urls = [urls]
        
        print(f"[NucleiModule WRAPPER] Escaneando {len(urls)} URLs")
        
        # Crear archivo temporal con URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for url in urls:
                # Limpiar URL
                url = str(url).strip()
                if url:
                    f.write(f"{url}\n")
            urls_file = f.name
        
        # Directorio de salida temporal
        output_dir = Path(tempfile.gettempdir()) / 'farosint_nuclei_scan'
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Llamar al módulo nuevo
            result = scan_vulnerabilities(
                urls_file=urls_file,
                output_dir=str(output_dir)
            )
            
            # Limpiar archivo temporal de URLs
            os.unlink(urls_file)
            
            vulnerabilities = result.get('vulnerabilities', [])
            
            print(f"[NucleiModule WRAPPER] Encontradas {len(vulnerabilities)} vulnerabilidades")
            
            # Retornar lista de vulnerabilidades (formato que espera orchestrator)
            return vulnerabilities
            
        except Exception as e:
            print(f"[NucleiModule WRAPPER] ERROR: {e}")
            import traceback
            traceback.print_exc()
            
            # Limpiar en caso de error
            if os.path.exists(urls_file):
                os.unlink(urls_file)
            
            return []
