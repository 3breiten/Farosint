#!/usr/bin/env python3
"""
FAROSINT Database Manager
Gestiona almacenamiento de resultados en SQLite
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager

class DatabaseManager:
    """Gestor de base de datos SQLite"""
    
    def __init__(self, db_path=None):
        """
        Inicializar gestor de base de datos
        
        Args:
            db_path: Ruta del archivo de base de datos
        """
        if db_path is None:
            db_path = Path.home() / "FAROSINT" / "gui" / "farosint.db"
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Crear tablas si no existen
        self._create_tables()
    
    @contextmanager
    def get_connection(self):
        """Context manager para conexión a BD"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Resultados como dict
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _create_tables(self):
        """Crear tablas de la base de datos"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Tabla de escaneos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    created_by TEXT DEFAULT 'web',
                    config JSON
                )
            ''')
            
            # Tabla de subdominios
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    source TEXT,
                    is_alive BOOLEAN DEFAULT 0,
                    http_status INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Tabla de servicios/puertos (UNIQUE evita duplicados por misma IP escaneada desde múltiples hostnames)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    service TEXT,
                    product TEXT,
                    version TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                    UNIQUE(scan_id, ip, port, protocol)
                )
            ''')
            
            # Tabla de vulnerabilidades
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    template_id TEXT,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    matched_at TEXT,
                    cve TEXT,
                    cvss REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Tabla de resultados raw (JSON completo)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS results_raw (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    results JSON NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            ''')
            
            # Índices para búsqueda rápida
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_services_scan ON services(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)')

            # Migración: deduplicar servicios existentes y agregar UNIQUE index
            try:
                cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_services_unique ON services(scan_id, ip, port, protocol)')
            except Exception:
                # Si falla, hay duplicados existentes: limpiar y reintentar
                cursor.execute('''
                    DELETE FROM services WHERE id NOT IN (
                        SELECT MIN(id) FROM services GROUP BY scan_id, ip, port, protocol
                    )
                ''')
                deleted = cursor.rowcount
                if deleted > 0:
                    print(f"[DB] Migración: eliminados {deleted} servicios duplicados")
                conn.commit()
                cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_services_unique ON services(scan_id, ip, port, protocol)')
    
    # =============================
    # Métodos para Scans
    # =============================
    
    def create_scan(self, scan_id, target, scan_type, config=None):
        """
        Crear nuevo escaneo
        
        Args:
            scan_id: ID único del escaneo
            target: Objetivo del escaneo
            scan_type: Tipo de escaneo (quick, full, custom)
            config: Configuración adicional (dict)
            
        Returns:
            ID del escaneo creado
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO scans (scan_id, target, scan_type, config)
                   VALUES (?, ?, ?, ?)''',
                (scan_id, target, scan_type, json.dumps(config) if config else None)
            )
            return cursor.lastrowid
    
    def update_scan_status(self, scan_id, status, end_time=None):
        """
        Actualizar estado de escaneo
        
        Args:
            scan_id: ID del escaneo
            status: Nuevo estado (running, completed, failed)
            end_time: Tiempo de finalización (opcional)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if end_time:
                cursor.execute(
                    'UPDATE scans SET status = ?, end_time = ? WHERE scan_id = ?',
                    (status, end_time, scan_id)
                )
            else:
                cursor.execute(
                    'UPDATE scans SET status = ? WHERE scan_id = ?',
                    (status, scan_id)
                )
    
    def get_scan(self, scan_id):
        """Obtener información de un escaneo"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_all_scans(self, limit=50, offset=0):
        """Obtener lista de escaneos con conteo de vulnerabilidades"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT s.*,
                          COUNT(DISTINCT v.id) as vuln_count
                   FROM scans s
                   LEFT JOIN vulnerabilities v ON s.scan_id = v.scan_id
                   GROUP BY s.scan_id
                   ORDER BY s.start_time DESC
                   LIMIT ? OFFSET ?''',
                (limit, offset)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scans_by_target(self, target):
        """Obtener escaneos de un objetivo específico"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM scans WHERE target = ? ORDER BY start_time DESC',
                (target,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_scan(self, scan_id):
        """
        Eliminar un escaneo y todos sus datos relacionados
        
        Args:
            scan_id: ID del escaneo a eliminar
            
        Returns:
            True si se eliminó exitosamente, False si no existe
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Verificar que existe
            cursor.execute('SELECT id FROM scans WHERE scan_id = ?', (scan_id,))
            if not cursor.fetchone():
                return False
            
            # Eliminar datos relacionados (cascada manual)
            cursor.execute('DELETE FROM subdomains WHERE scan_id = ?', (scan_id,))
            cursor.execute('DELETE FROM services WHERE scan_id = ?', (scan_id,))
            cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            cursor.execute('DELETE FROM results_raw WHERE scan_id = ?', (scan_id,))
            
            # Eliminar el escaneo
            cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
            
            return True
    
    # =============================
    # Métodos para Subdominios
    # =============================
    
    def add_subdomain(self, scan_id, subdomain, source=None, is_alive=False, http_status=None):
        """Agregar subdominio encontrado"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO subdomains (scan_id, subdomain, source, is_alive, http_status)
                   VALUES (?, ?, ?, ?, ?)''',
                (scan_id, subdomain, source, is_alive, http_status)
            )
            return cursor.lastrowid
    
    def get_subdomains(self, scan_id):
        """Obtener subdominios de un escaneo"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain',
                (scan_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    # =============================
    # Métodos para Servicios
    # =============================
    
    def add_service(self, scan_id, ip, port, protocol='tcp', service=None, product=None, version=None):
        """Agregar servicio detectado (ignora duplicados por misma IP+puerto+protocolo)"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT OR IGNORE INTO services (scan_id, ip, port, protocol, service, product, version)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (scan_id, ip, port, protocol, service, product, version)
            )
            return cursor.lastrowid
    
    def get_services(self, scan_id):
        """Obtener servicios de un escaneo"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM services WHERE scan_id = ? ORDER BY ip, port',
                (scan_id,)
            )
            return [dict(row) for row in cursor.fetchall()]
    
    # =============================
    # Métodos para Vulnerabilidades
    # =============================
    
    def add_vulnerability(self, scan_id, target, name, severity, **kwargs):
        """Agregar vulnerabilidad detectada"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO vulnerabilities 
                   (scan_id, target, template_id, name, severity, description, matched_at, cve, cvss)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    scan_id,
                    target,
                    kwargs.get('template_id'),
                    name,
                    severity,
                    kwargs.get('description'),
                    kwargs.get('matched_at'),
                    kwargs.get('cve'),
                    kwargs.get('cvss')
                )
            )
            return cursor.lastrowid
    
    def get_vulnerabilities(self, scan_id, severity=None):
        """Obtener vulnerabilidades de un escaneo"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if severity:
                cursor.execute(
                    'SELECT * FROM vulnerabilities WHERE scan_id = ? AND severity = ? ORDER BY severity DESC',
                    (scan_id, severity)
                )
            else:
                cursor.execute(
                    'SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC',
                    (scan_id,)
                )
            
            return [dict(row) for row in cursor.fetchall()]
    
    # =============================
    # Métodos para Resultados Raw
    # =============================
    
    def save_raw_results(self, scan_id, results):
        """Guardar resultados completos en JSON"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO results_raw (scan_id, results) VALUES (?, ?)',
                (scan_id, json.dumps(results))
            )
    
    def get_raw_results(self, scan_id):
        """Obtener resultados completos"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT results FROM results_raw WHERE scan_id = ?', (scan_id,))
            row = cursor.fetchone()
            return json.loads(row['results']) if row else None
    
    # =============================
    # Estadísticas
    # =============================
    
    def get_stats(self):
        """Obtener estadísticas generales"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Total de escaneos
            cursor.execute('SELECT COUNT(*) as total FROM scans')
            total_scans = cursor.fetchone()['total']
            
            # Escaneos por estado
            cursor.execute('SELECT status, COUNT(*) as count FROM scans GROUP BY status')
            by_status = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Total de vulnerabilidades
            cursor.execute('SELECT COUNT(*) as total FROM vulnerabilities')
            total_vulns = cursor.fetchone()['total']
            
            # Vulnerabilidades por severidad
            cursor.execute('SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity')
            by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            return {
                'total_scans': total_scans,
                'scans_by_status': by_status,
                'total_vulnerabilities': total_vulns,
                'vulnerabilities_by_severity': by_severity
            }


# Test
if __name__ == "__main__":
    db = DatabaseManager()
    
    # Crear escaneo de prueba
    scan_id = "test_20260118_120000"
    db.create_scan(scan_id, "example.com", "full")
    
    # Agregar subdominios
    db.add_subdomain(scan_id, "www.example.com", "subfinder", True, 200)
    db.add_subdomain(scan_id, "mail.example.com", "amass", True, 200)
    
    # Agregar vulnerabilidad
    db.add_vulnerability(
        scan_id,
        "www.example.com",
        "Apache RCE",
        "critical",
        cve="CVE-2021-41773",
        cvss=9.8
    )
    
    # Obtener estadísticas
    stats = db.get_stats()
    print(f"Estadísticas: {stats}")
