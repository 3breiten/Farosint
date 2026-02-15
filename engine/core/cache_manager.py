#!/usr/bin/env python3
"""
FAROSINT Cache Manager
Gestiona caché de resultados para evitar escaneos duplicados
"""

import os
import json
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta

class CacheManager:
    """Gestor de caché para resultados OSINT"""
    
    def __init__(self, cache_dir=None, ttl=86400):
        """
        Inicializar gestor de caché
        
        Args:
            cache_dir: Directorio de caché (default: ~/FAROSINT/engine/cache)
            ttl: Time To Live en segundos (default: 24 horas)
        """
        if cache_dir is None:
            cache_dir = os.path.expanduser("~/FAROSINT/engine/cache")
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        
    def _get_cache_key(self, tool, target, params=None):
        """
        Generar clave única para caché
        
        Args:
            tool: Nombre de la herramienta
            target: Objetivo (dominio, IP, URL)
            params: Parámetros adicionales
            
        Returns:
            Hash MD5 de la clave
        """
        key_parts = [tool, target]
        
        if params:
            # Ordenar parámetros para consistencia
            params_str = json.dumps(params, sort_keys=True)
            key_parts.append(params_str)
        
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key):
        """Obtener ruta del archivo de caché"""
        return self.cache_dir / f"{cache_key}.json"
    
    def get(self, tool, target, params=None):
        """
        Obtener resultado del caché si existe y es válido
        
        Args:
            tool: Nombre de la herramienta
            target: Objetivo
            params: Parámetros adicionales
            
        Returns:
            Resultado cacheado o None si no existe/expiró
        """
        cache_key = self._get_cache_key(tool, target, params)
        cache_path = self._get_cache_path(cache_key)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                cached_data = json.load(f)
            
            # Verificar TTL
            cached_time = cached_data.get('timestamp', 0)
            current_time = time.time()
            
            if (current_time - cached_time) > self.ttl:
                # Caché expirado
                cache_path.unlink()  # Eliminar archivo expirado
                return None
            
            return cached_data.get('result')
            
        except (json.JSONDecodeError, KeyError, IOError):
            # Caché corrupto
            if cache_path.exists():
                cache_path.unlink()
            return None
    
    def set(self, tool, target, result, params=None):
        """
        Guardar resultado en caché
        
        Args:
            tool: Nombre de la herramienta
            target: Objetivo
            result: Resultado a cachear
            params: Parámetros adicionales
        """
        cache_key = self._get_cache_key(tool, target, params)
        cache_path = self._get_cache_path(cache_key)
        
        cache_data = {
            'tool': tool,
            'target': target,
            'params': params,
            'timestamp': time.time(),
            'result': result
        }
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except IOError as e:
            print(f"[!] Error guardando caché: {e}")
    
    def clear_expired(self):
        """Limpiar caché expirado"""
        current_time = time.time()
        cleared = 0
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                
                cached_time = cached_data.get('timestamp', 0)
                
                if (current_time - cached_time) > self.ttl:
                    cache_file.unlink()
                    cleared += 1
                    
            except (json.JSONDecodeError, KeyError, IOError):
                # Archivo corrupto, eliminar
                cache_file.unlink()
                cleared += 1
        
        return cleared
    
    def clear_all(self):
        """Limpiar todo el caché"""
        cleared = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            cleared += 1
        return cleared
    
    def get_stats(self):
        """Obtener estadísticas del caché"""
        total_files = len(list(self.cache_dir.glob("*.json")))
        total_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))
        
        # Calcular edad promedio
        ages = []
        current_time = time.time()
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cached_data = json.load(f)
                age = current_time - cached_data.get('timestamp', current_time)
                ages.append(age)
            except:
                pass
        
        avg_age = sum(ages) / len(ages) if ages else 0
        
        return {
            'total_entries': total_files,
            'total_size_mb': total_size / (1024 * 1024),
            'average_age_hours': avg_age / 3600
        }


# Ejemplo de uso
if __name__ == "__main__":
    cache = CacheManager()
    
    # Guardar resultado
    cache.set("subfinder", "example.com", ["www.example.com", "mail.example.com"])
    
    # Recuperar resultado
    result = cache.get("subfinder", "example.com")
    print(f"Resultado cacheado: {result}")
    
    # Estadísticas
    stats = cache.get_stats()
    print(f"Estadísticas: {stats}")
