#!/usr/bin/env python3
"""
FAROSINT System Health Check
Monitoreo y limpieza automática del sistema
"""

import os
import sys
import psutil
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

class SystemHealthCheck:
    """Monitor de salud del sistema FAROSINT"""

    def __init__(self, db_path=None):
        """
        Inicializar health check

        Args:
            db_path: Ruta a la base de datos SQLite
        """
        if db_path is None:
            self.db_path = Path.home() / "FAROSINT" / "gui" / "farosint.db"
        else:
            self.db_path = Path(db_path)

        self.issues = []
        self.actions_taken = []

    def log_issue(self, severity, message):
        """Registrar un problema encontrado"""
        self.issues.append({
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        print(f"[{severity}] {message}")

    def log_action(self, action):
        """Registrar una acción tomada"""
        self.actions_taken.append({
            'action': action,
            'timestamp': datetime.now().isoformat()
        })
        print(f"[ACTION] {action}")

    def check_zombie_processes(self, kill=False, max_minutes=30):
        """
        Detectar procesos zombie de herramientas OSINT

        Args:
            kill: Si True, mata los procesos zombie
            max_minutes: Minutos máximos antes de considerar zombie (default: 30)

        Returns:
            Lista de PIDs encontrados
        """
        print(f"\n[1/5] Verificando procesos zombie (>{max_minutes} min)...")

        zombie_pids = []
        osint_tools = ['amass', 'subfinder', 'httpx', 'nmap', 'nuclei', 'masscan']

        # Buscar procesos de herramientas OSINT
        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()

                # Verificar si es una herramienta OSINT
                if any(tool in proc_name for tool in osint_tools):
                    # Calcular tiempo de ejecución
                    create_time = datetime.fromtimestamp(proc_info['create_time'])
                    runtime = datetime.now() - create_time

                    # Si lleva más del threshold, es sospechoso
                    if runtime > timedelta(minutes=max_minutes):
                        zombie_pids.append({
                            'pid': proc_info['pid'],
                            'name': proc_name,
                            'runtime': str(runtime),
                            'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                        })

                        self.log_issue(
                            'WARNING',
                            f"Proceso zombie detectado: PID {proc_info['pid']} ({proc_name}) - "
                            f"Corriendo hace {int(runtime.total_seconds() / 60)} minutos"
                        )

                        if kill:
                            try:
                                proc.kill()
                                self.log_action(f"Proceso zombie eliminado: PID {proc_info['pid']}")
                            except psutil.AccessDenied:
                                self.log_issue('ERROR', f"No se pudo matar PID {proc_info['pid']}: Acceso denegado")
                            except Exception as e:
                                self.log_issue('ERROR', f"Error matando PID {proc_info['pid']}: {e}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not zombie_pids:
            print("  ✓ No se encontraron procesos zombie")
        else:
            print(f"  ⚠ {len(zombie_pids)} proceso(s) zombie detectado(s)")

        return zombie_pids

    def check_stuck_scans(self, mark_failed=False, max_hours=2):
        """
        Detectar escaneos colgados en la BD

        Args:
            mark_failed: Si True, marca los escaneos como fallidos
            max_hours: Horas máximas antes de considerar un escaneo colgado

        Returns:
            Lista de escaneos colgados
        """
        # Mostrar en minutos si es < 1 hora
        threshold_display = f">{int(max_hours * 60)} min" if max_hours < 1 else f">{max_hours}h"
        print(f"\n[2/5] Verificando escaneos colgados ({threshold_display})...")

        if not self.db_path.exists():
            self.log_issue('ERROR', f"Base de datos no encontrada: {self.db_path}")
            return []

        stuck_scans = []

        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Buscar escaneos "running" antiguos
            cursor.execute("""
                SELECT scan_id, target, start_time,
                       (julianday('now') - julianday(start_time)) * 24 as hours_running
                FROM scans
                WHERE status = 'running'
                  AND (julianday('now') - julianday(start_time)) * 24 > ?
                ORDER BY start_time ASC
            """, (max_hours,))

            scans = cursor.fetchall()

            for scan in scans:
                stuck_scans.append({
                    'scan_id': scan['scan_id'],
                    'target': scan['target'],
                    'start_time': scan['start_time'],
                    'hours_running': round(scan['hours_running'], 2)
                })

                self.log_issue(
                    'WARNING',
                    f"Escaneo colgado: {scan['target']} - "
                    f"Corriendo hace {round(scan['hours_running'], 1)} horas"
                )

                if mark_failed:
                    cursor.execute("""
                        UPDATE scans
                        SET status = 'failed',
                            end_time = datetime('now')
                        WHERE scan_id = ?
                    """, (scan['scan_id'],))

                    self.log_action(f"Escaneo marcado como fallido: {scan['scan_id']}")

            if mark_failed and stuck_scans:
                conn.commit()

            conn.close()

            if not stuck_scans:
                print("  ✓ No se encontraron escaneos colgados")
            else:
                print(f"  ⚠ {len(stuck_scans)} escaneo(s) colgado(s) detectado(s)")

        except Exception as e:
            self.log_issue('ERROR', f"Error verificando escaneos: {e}")

        return stuck_scans

    def check_temp_files(self, clean=False, max_days=7):
        """
        Verificar archivos temporales antiguos

        Args:
            clean: Si True, elimina archivos viejos
            max_days: Días de antigüedad antes de limpiar

        Returns:
            Lista de archivos encontrados
        """
        print(f"\n[3/5] Verificando archivos temporales (>{max_days} días)...")

        old_files = []
        temp_dirs = [
            '/tmp',
            Path.home() / '.farosint' / 'cache'
        ]

        cutoff_time = datetime.now() - timedelta(days=max_days)

        for temp_dir in temp_dirs:
            if not Path(temp_dir).exists():
                continue

            try:
                for pattern in ['tmp*', '*.tmp', 'farosint_*']:
                    for file_path in Path(temp_dir).glob(pattern):
                        if file_path.is_file():
                            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)

                            if mtime < cutoff_time:
                                size_mb = file_path.stat().st_size / (1024 * 1024)
                                old_files.append({
                                    'path': str(file_path),
                                    'age_days': (datetime.now() - mtime).days,
                                    'size_mb': round(size_mb, 2)
                                })

                                if clean:
                                    try:
                                        file_path.unlink()
                                        self.log_action(f"Archivo temporal eliminado: {file_path.name}")
                                    except Exception as e:
                                        self.log_issue('ERROR', f"Error eliminando {file_path}: {e}")

            except Exception as e:
                self.log_issue('ERROR', f"Error verificando {temp_dir}: {e}")

        if old_files and not clean:
            total_mb = sum(f['size_mb'] for f in old_files)
            print(f"  ⚠ {len(old_files)} archivo(s) temporal(es) antiguo(s) ({total_mb:.1f} MB)")
        elif old_files and clean:
            print(f"  ✓ {len(old_files)} archivo(s) limpiado(s)")
        else:
            print("  ✓ No se encontraron archivos temporales antiguos")

        return old_files

    def check_tools_availability(self):
        """
        Verificar que las herramientas OSINT estén disponibles

        Returns:
            Dict con estado de cada herramienta
        """
        print("\n[4/5] Verificando disponibilidad de herramientas...")

        tools = {
            'subfinder': '/home/farosint/go/bin/subfinder',
            'amass': '/usr/local/bin/amass',
            'httpx': '/home/farosint/go/bin/httpx',
            'nmap': '/usr/bin/nmap',
            'nuclei': '/home/farosint/go/bin/nuclei',
            'whatweb': '/usr/bin/whatweb'
        }

        status = {}

        for tool, path in tools.items():
            if Path(path).exists() and os.access(path, os.X_OK):
                status[tool] = 'OK'
            else:
                status[tool] = 'NOT_FOUND'
                self.log_issue('ERROR', f"Herramienta no disponible: {tool} ({path})")

        available = sum(1 for s in status.values() if s == 'OK')
        print(f"  {'✓' if available == len(tools) else '⚠'} {available}/{len(tools)} herramientas disponibles")

        return status

    def check_database_integrity(self):
        """
        Verificar integridad de la base de datos

        Returns:
            Dict con resultado de la verificación
        """
        print("\n[5/5] Verificando integridad de base de datos...")

        if not self.db_path.exists():
            self.log_issue('CRITICAL', f"Base de datos no existe: {self.db_path}")
            return {'status': 'NOT_FOUND'}

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Verificar integridad
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()[0]

            if result != 'ok':
                self.log_issue('CRITICAL', f"Integridad de BD comprometida: {result}")
                conn.close()
                return {'status': 'CORRUPTED', 'error': result}

            # Obtener estadísticas
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
            running_scans = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulns = cursor.fetchone()[0]

            conn.close()

            print(f"  ✓ Base de datos OK")
            print(f"    - Total escaneos: {total_scans}")
            print(f"    - Escaneos activos: {running_scans}")
            print(f"    - Total vulnerabilidades: {total_vulns}")

            return {
                'status': 'OK',
                'total_scans': total_scans,
                'running_scans': running_scans,
                'total_vulnerabilities': total_vulns
            }

        except Exception as e:
            self.log_issue('ERROR', f"Error verificando BD: {e}")
            return {'status': 'ERROR', 'error': str(e)}

    def run_full_check(self, auto_fix=False):
        """
        Ejecutar verificación completa del sistema

        Args:
            auto_fix: Si True, corrige problemas automáticamente

        Returns:
            Dict con resumen de resultados
        """
        print("="*60)
        print("  FAROSINT - Health Check del Sistema")
        print("="*60)
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Auto-Fix: {'Habilitado' if auto_fix else 'Deshabilitado'}")
        print()

        # Ejecutar todas las verificaciones (threshold reducido a 30 min)
        zombie_procs = self.check_zombie_processes(kill=auto_fix, max_minutes=30)
        stuck_scans = self.check_stuck_scans(mark_failed=auto_fix, max_hours=0.5)
        old_files = self.check_temp_files(clean=auto_fix)
        tools_status = self.check_tools_availability()
        db_status = self.check_database_integrity()

        # Resumen
        print("\n" + "="*60)
        print("  RESUMEN")
        print("="*60)

        total_issues = len(self.issues)
        total_actions = len(self.actions_taken)

        if total_issues == 0:
            print("✓ Sistema OK - No se encontraron problemas")
        else:
            print(f"⚠ {total_issues} problema(s) detectado(s)")

            # Agrupar por severidad
            critical = sum(1 for i in self.issues if i['severity'] == 'CRITICAL')
            errors = sum(1 for i in self.issues if i['severity'] == 'ERROR')
            warnings = sum(1 for i in self.issues if i['severity'] == 'WARNING')

            if critical > 0:
                print(f"  - CRITICAL: {critical}")
            if errors > 0:
                print(f"  - ERROR: {errors}")
            if warnings > 0:
                print(f"  - WARNING: {warnings}")

        if auto_fix and total_actions > 0:
            print(f"\n✓ {total_actions} acción(es) correctiva(s) ejecutada(s)")

        print("="*60)

        return {
            'timestamp': datetime.now().isoformat(),
            'issues': self.issues,
            'actions_taken': self.actions_taken,
            'zombie_processes': zombie_procs,
            'stuck_scans': stuck_scans,
            'old_temp_files': old_files,
            'tools_status': tools_status,
            'database_status': db_status
        }


def main():
    """Función principal para ejecutar desde CLI"""
    import argparse

    parser = argparse.ArgumentParser(description='FAROSINT System Health Check')
    parser.add_argument('--auto-fix', action='store_true',
                        help='Corregir problemas automáticamente')
    parser.add_argument('--db-path', type=str,
                        help='Ruta a la base de datos SQLite')
    parser.add_argument('--json', action='store_true',
                        help='Output en formato JSON')

    args = parser.parse_args()

    # Ejecutar health check
    health_check = SystemHealthCheck(db_path=args.db_path)
    results = health_check.run_full_check(auto_fix=args.auto_fix)

    # Output
    if args.json:
        import json
        print(json.dumps(results, indent=2))

    # Exit code según severidad de problemas
    if any(i['severity'] == 'CRITICAL' for i in results['issues']):
        sys.exit(2)
    elif any(i['severity'] == 'ERROR' for i in results['issues']):
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
