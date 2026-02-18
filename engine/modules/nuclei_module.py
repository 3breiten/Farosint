#!/usr/bin/env python3
"""
WRAPPER: Llama al nuevo módulo vulnerability_scan.py
Mantiene compatibilidad con orchestrator.py
"""
from pathlib import Path
import tempfile
import os
import sys
import time

# Importar el módulo nuevo
sys.path.insert(0, str(Path(__file__).parent))
from vulnerability_scan import scan_vulnerabilities

class NucleiModule:
    """Wrapper para mantener compatibilidad con orchestrator"""

    def __init__(self, timeout=None, cache_manager=None, config=None):
        self.timeout = timeout
        self.cache_manager = cache_manager
        self.config = config or {}

    def run(self, urls):
        """
        Ejecuta escaneo de vulnerabilidades

        Args:
            urls: Lista de URLs o string única

        Returns:
            Lista de vulnerabilidades (para compatibilidad con orchestrator)
        """
        if isinstance(urls, str):
            urls = [urls]

        url_count = len(urls)
        print(f"[Nuclei] Escaneando {url_count} URLs")

        # Crear archivo temporal con URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for url in urls:
                url = str(url).strip()
                if url:
                    f.write(f"{url}\n")
            urls_file = f.name

        # Directorio ÚNICO por escaneo (evita que scans concurrentes se pisen)
        scan_ts = int(time.time() * 1000)
        output_dir = Path(tempfile.gettempdir()) / f'farosint_nuclei_{scan_ts}'
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            result = scan_vulnerabilities(
                urls_file=urls_file,
                output_dir=str(output_dir)
            )

            os.unlink(urls_file)

            vulnerabilities = result.get('vulnerabilities', [])

            # Advertir si Nuclei no encontró nada en múltiples URLs
            if url_count > 0 and len(vulnerabilities) == 0:
                error = result.get('error', '')
                if error:
                    print(f"[Nuclei] WARNING: 0 vulnerabilidades en {url_count} URLs (error: {error})")
                else:
                    print(f"[Nuclei] 0 vulnerabilidades en {url_count} URLs "
                          f"(puede ser normal o WAF bloqueando scanner)")
            else:
                print(f"[Nuclei] {len(vulnerabilities)} vulnerabilidades encontradas")

            return vulnerabilities

        except Exception as e:
            print(f"[Nuclei] ERROR: {e}")
            import traceback
            traceback.print_exc()

            if os.path.exists(urls_file):
                os.unlink(urls_file)

            return []
