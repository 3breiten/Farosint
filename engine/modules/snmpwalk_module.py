#!/usr/bin/env python3
"""
FAROSINT SNMP Module
Enumeración SNMP: info del sistema, interfaces de red, usuarios, procesos
"""

import subprocess
import re
from .base_module import BaseModule


# Community strings comunes a probar
COMMON_COMMUNITIES = ['public', 'private', 'community', 'manager', 'admin', 'default']

# OIDs relevantes
OIDS = {
    'sysDescr':    '1.3.6.1.2.1.1.1.0',    # Descripción del sistema
    'sysName':     '1.3.6.1.2.1.1.5.0',    # Hostname
    'sysContact':  '1.3.6.1.2.1.1.4.0',    # Contacto
    'sysLocation': '1.3.6.1.2.1.1.6.0',    # Ubicación
    'sysUpTime':   '1.3.6.1.2.1.1.3.0',    # Uptime
    'interfaces':  '1.3.6.1.2.1.2.2.1',    # Interfaces de red
    'ipRouting':   '1.3.6.1.2.1.4.21',     # Tabla de ruteo
    'processes':   '1.3.6.1.2.1.25.4.2',   # Procesos (HOST-RESOURCES-MIB)
    'software':    '1.3.6.1.2.1.25.6.3',   # Software instalado
    'users':       '1.3.6.1.4.1.77.1.2.25', # Usuarios Windows (LAN Manager)
}


class SNMPModule(BaseModule):
    """Módulo para enumeración SNMP"""

    def __init__(self, timeout=30, cache_manager=None):
        super().__init__("SNMPWalk", timeout, cache_manager)

    def run(self, target, **kwargs):
        """
        Escanear SNMP en el target

        Returns:
            Dict con información del sistema via SNMP
        """
        self.log(f"Iniciando enumeración SNMP de: {target}")

        snmpwalk_bin = self.get_tool_path('snmpwalk')
        if not snmpwalk_bin:
            self.log("snmpwalk no encontrado", "WARNING")
            return self._empty_result()

        # Probar community strings
        working_community = None
        for community in COMMON_COMMUNITIES:
            if self._test_community(snmpwalk_bin, target, community):
                working_community = community
                self.log(f"Community string válida: '{community}'")
                break

        if not working_community:
            self.log("No se encontró community string SNMP válida")
            return self._empty_result()

        # Recolectar información
        result = self._empty_result()
        result['community'] = working_community

        # Info del sistema
        sys_info = self._get_system_info(snmpwalk_bin, target, working_community)
        result.update(sys_info)

        # Procesos
        processes = self._get_processes(snmpwalk_bin, target, working_community)
        result['processes'] = processes[:20]  # Limitar a 20

        # Software instalado
        software = self._get_software(snmpwalk_bin, target, working_community)
        result['software'] = software[:30]  # Limitar a 30

        # Marcar como vulnerabilidad si community es 'public'
        if working_community == 'public':
            result['vulnerability'] = {
                'name': 'SNMP Community String por defecto (public)',
                'severity': 'medium',
                'description': f'El target {target} responde a SNMP con community string "public" (valor por defecto). Expone información del sistema.',
                'cve': 'CVE-2002-0013',
                'cvss': 5.0
            }

        self.log(f"SNMP: {result.get('hostname', 'N/A')} | OS: {result.get('os_description', 'N/A')[:50]}")
        return result

    def _test_community(self, snmpwalk_bin, target, community):
        """Probar si una community string funciona"""
        try:
            result = subprocess.run(
                [snmpwalk_bin, '-v2c', '-c', community, '-t', '3', target, OIDS['sysDescr']],
                capture_output=True, text=True, timeout=8
            )
            return result.returncode == 0 and 'SNMPv2-MIB' in result.stdout
        except Exception:
            return False

    def _get_system_info(self, snmpwalk_bin, target, community):
        """Obtener información básica del sistema"""
        info = {}
        for name, oid in [('sysDescr', OIDS['sysDescr']),
                          ('sysName', OIDS['sysName']),
                          ('sysContact', OIDS['sysContact']),
                          ('sysLocation', OIDS['sysLocation'])]:
            try:
                result = subprocess.run(
                    [snmpwalk_bin, '-v2c', '-c', community, '-t', '3', target, oid],
                    capture_output=True, text=True, timeout=10
                )
                value = self._extract_value(result.stdout)
                if value:
                    if name == 'sysDescr':
                        info['os_description'] = value
                    elif name == 'sysName':
                        info['hostname'] = value
                    elif name == 'sysContact':
                        info['contact'] = value
                    elif name == 'sysLocation':
                        info['location'] = value
            except Exception:
                pass
        return info

    def _get_processes(self, snmpwalk_bin, target, community):
        """Obtener lista de procesos"""
        processes = []
        try:
            result = subprocess.run(
                [snmpwalk_bin, '-v2c', '-c', community, '-t', '5', target, OIDS['processes']],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.split('\n'):
                value = self._extract_value(line)
                if value and value not in processes:
                    processes.append(value)
        except Exception:
            pass
        return processes

    def _get_software(self, snmpwalk_bin, target, community):
        """Obtener software instalado"""
        software = []
        try:
            result = subprocess.run(
                [snmpwalk_bin, '-v2c', '-c', community, '-t', '5', target, OIDS['software']],
                capture_output=True, text=True, timeout=20
            )
            for line in result.stdout.split('\n'):
                value = self._extract_value(line)
                if value and value not in software:
                    software.append(value)
        except Exception:
            pass
        return software

    def _extract_value(self, line):
        """Extraer valor de una línea de snmpwalk"""
        match = re.search(r'STRING:\s*"?([^"]+)"?', line)
        if match:
            return match.group(1).strip()
        match = re.search(r'Timeticks:\s*\([\d]+\)\s*(.+)', line)
        if match:
            return match.group(1).strip()
        return None

    def _empty_result(self):
        return {
            'community': None,
            'os_description': '',
            'hostname': '',
            'contact': '',
            'location': '',
            'processes': [],
            'software': [],
            'vulnerability': None
        }
