#!/usr/bin/env python3
"""
FAROSINT - Actualización de Base de Datos
Agrega columnas para MITRE/OWASP/CVE/Remediation
"""

import sqlite3
from pathlib import Path

DB_PATH = Path.home() / "FAROSINT" / "gui" / "farosint.db"

def update_database():
    """Actualiza el esquema de la base de datos"""
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    print("="*80)
    print("FAROSINT - Actualización de Base de Datos")
    print("="*80)
    print()
    
    # Verificar tabla vulnerabilities existe
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='vulnerabilities'
    """)
    
    if not cursor.fetchone():
        print("❌ Tabla 'vulnerabilities' no existe")
        print("   Ejecuta primero un escaneo desde el dashboard")
        conn.close()
        return
    
    # Obtener columnas actuales
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    existing_columns = [row[1] for row in cursor.fetchall()]
    
    print(f"Columnas actuales: {len(existing_columns)}")
    print()
    
    # Columnas a agregar
    new_columns = {
        'cve': 'TEXT',
        'cvss_score': 'REAL',
        'mitre_technique': 'TEXT',
        'mitre_url': 'TEXT',
        'owasp_category': 'TEXT',
        'owasp_url': 'TEXT',
        'cve_details_url': 'TEXT',
        'nvd_url': 'TEXT',
        'remediation_priority': 'TEXT',
        'remediation_steps': 'TEXT',
        'tags': 'TEXT',
        'references': 'TEXT'  # JSON con todas las referencias
    }
    
    added = 0
    skipped = 0
    
    for column, datatype in new_columns.items():
        if column not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {column} {datatype}")
                print(f"✓ Agregada columna: {column} ({datatype})")
                added += 1
            except Exception as e:
                print(f"✗ Error agregando {column}: {e}")
        else:
            print(f"⊙ Columna ya existe: {column}")
            skipped += 1
    
    conn.commit()
    conn.close()
    
    print()
    print("="*80)
    print(f"✓ Actualización completada")
    print(f"  Columnas agregadas: {added}")
    print(f"  Columnas existentes: {skipped}")
    print("="*80)
    print()
    print("Ahora el dashboard puede guardar información de MITRE/OWASP/CVE")
    print()

if __name__ == "__main__":
    update_database()
