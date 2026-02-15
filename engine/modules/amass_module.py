#!/usr/bin/env python3
"""
FAROSINT Amass Module
Enumeración profunda de subdominios
"""

import os
import json
import signal
import subprocess
from pathlib import Path
from .base_module import BaseModule

class AmassModule(BaseModule):
    """Módulo para Amass"""

    def __init__(self, timeout=1800, cache_manager=None):
        super().__init__("Amass", timeout, cache_manager)

    def execute_command(self, cmd, cwd=None):
        """
        Sobrescribir execute_command para manejar procesos hijos de Amass

        Amass lanza procesos hijos (amass engine) que se convierten en zombies
        cuando el padre muere. Usamos process groups para matarlos todos.

        Args:
            cmd: Comando a ejecutar (lista)
            cwd: Directorio de trabajo

        Returns:
            Tuple (stdout, stderr, returncode)
        """
        try:
            # Crear proceso en nuevo process group (preexec_fn=os.setsid)
            # Esto permite matar todo el grupo después
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                text=True,
                preexec_fn=os.setsid  # Crear nuevo session ID
            )

            stdout, stderr = process.communicate(timeout=self.timeout)
            returncode = process.returncode

            return stdout, stderr, returncode

        except subprocess.TimeoutExpired:
            # Matar TODO el process group, incluyendo hijos
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                # Esperar un poco para que se cierre limpiamente
                process.wait(timeout=5)
            except:
                # Si no se cerró, matar con SIGKILL
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except:
                    pass

            # CRÍTICO: Amass lanza procesos daemon que escapan del process group
            # Matarlos explícitamente por nombre
            try:
                subprocess.run(['pkill', '-9', 'amass'], check=False, timeout=2)
            except:
                pass

            stdout, stderr = process.communicate()
            raise TimeoutError(f"{self.name} excedió timeout de {self.timeout}s")

        except Exception as e:
            raise RuntimeError(f"Error ejecutando {self.name}: {str(e)}")
    
    def run(self, domain, **kwargs):
        """
        Ejecutar Amass
        
        Args:
            domain: Dominio objetivo
            **kwargs: Parámetros adicionales
                - mode: 'passive' o 'active' (default: 'passive')
                - brute: Fuerza bruta (default: False)
                
        Returns:
            Lista de subdominios encontrados
        """
        mode = kwargs.get('mode', 'passive')
        brute = kwargs.get('brute', False)
        
        self.log(f"Iniciando Amass en modo {mode} para: {domain}")
        
        # Verificar caché
        params = {'mode': mode, 'brute': brute}
        cached_result = self.check_cache(domain, params)
        
        if cached_result:
            self.log(f"Usando resultado cacheado ({len(cached_result)} subdominios)")
            return cached_result
        
        # Crear archivo temporal
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_output = f.name
        
        try:
            # Construir comando con ruta absoluta
            amass_path = self.get_tool_path('amass')
            cmd = [amass_path, 'enum', '-d', domain, '-o', temp_output]

            # CRÍTICO: Usar timeout nativo de Amass para evitar procesos huérfanos
            # Amass lanza múltiples procesos hijos (amass engine) que no mueren con kill del padre
            timeout_minutes = max(1, int(self.timeout / 60))  # Convertir seg -> min
            cmd.extend(['-timeout', str(timeout_minutes)])

            if mode == 'passive':
                cmd.append('-passive')
            elif mode == 'active':
                cmd.append('-active')

            if brute and mode == 'active':
                cmd.append('-brute')

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
            # Intentar leer resultados parciales
            if os.path.exists(temp_output):
                with open(temp_output, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                self.log(f"Resultados parciales: {len(subdomains)} subdominios")
                return subdomains
            return []
        
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            return []
        
        finally:
            if os.path.exists(temp_output):
                os.unlink(temp_output)
