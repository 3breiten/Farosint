#!/usr/bin/env python3
"""
FAROSINT Base Module
Clase base para todos los módulos de herramientas OSINT
"""

import subprocess
import json
import os
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from abc import ABC, abstractmethod

class BaseModule(ABC):
    """Clase base abstracta para módulos OSINT"""

    def __init__(self, name, timeout=600, cache_manager=None):
        """
        Inicializar módulo

        Args:
            name: Nombre del módulo
            timeout: Timeout en segundos
            cache_manager: Gestor de caché (opcional)
        """
        self.name = name
        self.timeout = timeout
        self.cache_manager = cache_manager

        # Directorios
        self.engine_dir = Path.home() / "FAROSINT" / "engine"
        self.output_dir = self.engine_dir / "output"
        self.logs_dir = self.engine_dir / "logs"

        # Crear directorios si no existen
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        # Mapeo de comandos a rutas absolutas
        self.tool_paths = self._find_tool_paths()

    def _find_tool_paths(self):
        """
        Encuentra las rutas absolutas de las herramientas OSINT

        Returns:
            Dict con mapeo de comando -> ruta absoluta
        """
        home = Path.home()
        paths = {}

        # Rutas EXACTAS conocidas para cada herramienta (orden de prioridad)
        # Esto elimina la ambigüedad del PATH del sistema
        tool_candidates = {
            'subfinder': [
                home / 'go' / 'bin' / 'subfinder',
            ],
            'httpx': [
                home / 'go' / 'bin' / 'httpx',
                # NO incluir ~/.local/bin/httpx (es el cliente HTTP de Python, no la herramienta OSINT)
            ],
            'nuclei': [
                home / 'go' / 'bin' / 'nuclei',
            ],
            'amass': [
                Path('/usr/local/bin/amass'),
                home / 'go' / 'bin' / 'amass',
            ],
            'nmap': [
                Path('/usr/bin/nmap'),
            ],
            'whatweb': [
                Path('/usr/bin/whatweb'),
            ],
            'gobuster': [
                Path('/usr/bin/gobuster'),
            ],
            'dnsrecon': [
                Path('/usr/bin/dnsrecon'),
            ],
            'rustscan': [
                Path('/usr/local/bin/rustscan'),
                Path('/usr/bin/rustscan'),
            ],
            'theHarvester': [
                home / 'FAROSINT' / 'bin' / 'theHarvester',
            ],
            'nikto': [
                home / 'tools' / 'nikto' / 'program' / 'nikto.pl',
            ],
        }

        for tool, candidates in tool_candidates.items():
            for candidate in candidates:
                if candidate.exists() and os.access(candidate, os.X_OK):
                    paths[tool] = str(candidate)
                    break

        return paths

    def get_tool_path(self, tool_name):
        """
        Obtiene la ruta absoluta de una herramienta

        Args:
            tool_name: Nombre de la herramienta

        Returns:
            Ruta absoluta o el nombre original si no se encuentra
        """
        path = self.tool_paths.get(tool_name)
        if path is None:
            self.log(f"Herramienta '{tool_name}' no encontrada en rutas conocidas", "WARNING")
            return tool_name
        return path
    
    @abstractmethod
    def run(self, target, **kwargs):
        """
        Ejecutar módulo (debe ser implementado por subclases)
        
        Args:
            target: Objetivo (dominio, IP, URL, etc.)
            **kwargs: Parámetros adicionales
            
        Returns:
            Resultados del módulo
        """
        pass
    
    def execute_command(self, cmd, cwd=None):
        """
        Ejecutar comando de shell con timeout
        
        Args:
            cmd: Comando a ejecutar (lista)
            cwd: Directorio de trabajo
            
        Returns:
            Tuple (stdout, stderr, returncode)
        """
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.timeout)
            returncode = process.returncode
            
            return stdout, stderr, returncode
            
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise TimeoutError(f"{self.name} excedió timeout de {self.timeout}s")
        
        except Exception as e:
            raise RuntimeError(f"Error ejecutando {self.name}: {str(e)}")
    
    def save_results(self, target, results, scan_id=None):
        """
        Guardar resultados en archivo
        
        Args:
            target: Objetivo del escaneo
            results: Resultados a guardar
            scan_id: ID del escaneo (opcional)
            
        Returns:
            Path del archivo guardado
        """
        if scan_id is None:
            scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Crear directorio para el objetivo
        target_clean = target.replace("://", "_").replace("/", "_").replace(".", "_")
        target_dir = self.output_dir / f"{target_clean}_{scan_id}"
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Guardar resultados
        output_file = target_dir / f"{self.name.lower()}.json"
        
        output_data = {
            'module': self.name,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        return output_file
    
    def log(self, message, level="INFO"):
        """
        Escribir en log
        
        Args:
            message: Mensaje a loguear
            level: Nivel (INFO, WARNING, ERROR)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] [{self.name}] {message}\n"
        
        log_file = self.logs_dir / f"{self.name.lower()}.log"
        
        with open(log_file, 'a') as f:
            f.write(log_message)
        
        # También imprimir en consola
        print(log_message.strip())
    
    def check_cache(self, target, params=None):
        """
        Verificar si hay resultado en caché
        
        Args:
            target: Objetivo
            params: Parámetros adicionales
            
        Returns:
            Resultado cacheado o None
        """
        if self.cache_manager is None:
            return None
        
        return self.cache_manager.get(self.name, target, params)
    
    def update_cache(self, target, result, params=None):
        """
        Actualizar caché con resultado
        
        Args:
            target: Objetivo
            result: Resultado a cachear
            params: Parámetros adicionales
        """
        if self.cache_manager is not None:
            self.cache_manager.set(self.name, target, result, params)
