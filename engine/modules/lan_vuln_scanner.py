#!/usr/bin/env python3
"""
FAROSINT LAN Vulnerability Scanner
Busca CVEs conocidos para OS y servicios detectados en escaneos LAN
Fuente: NVD (National Vulnerability Database) API v2
"""

import requests
import time
import re
from typing import List, Dict, Any


# Mapa de CPE conocidos basado en output de smb-os-discovery
OS_CPE_MAP = {
    'windows 7':         'cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*',
    'windows xp':        'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*',
    'windows vista':     'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*',
    'windows server 2003': 'cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*',
    'windows server 2008': 'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*',
    'windows server 2012': 'cpe:2.3:o:microsoft:windows_server_2012:-:-:*:*:*:*:*:*',
    'windows 10':        'cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*',
    'windows 11':        'cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:*:*',
    'ubuntu':            'cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*',
    'debian':            'cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*',
    'centos':            'cpe:2.3:o:centos:centos:*:*:*:*:*:*:*:*',
    'android':           'cpe:2.3:o:google:android:*:*:*:*:*:*:*:*',
}

# CVEs críticos de Windows 7 conocidos (fallback si NVD no responde)
WINDOWS7_KNOWN_CVES = [
    {
        'cve': 'CVE-2017-0144',
        'name': 'MS17-010 EternalBlue SMBv1 RCE (WannaCry)',
        'severity': 'critical',
        'cvss': 9.8,
        'description': 'Vulnerabilidad de ejecución remota de código en SMBv1. Explotada masivamente por WannaCry y NotPetya.',
        'remediation': 'Aplicar MS17-010. Deshabilitar SMBv1. Aislar el sistema.'
    },
    {
        'cve': 'CVE-2019-0708',
        'name': 'BlueKeep - RDP RCE crítico sin autenticación',
        'severity': 'critical',
        'cvss': 9.8,
        'description': 'Vulnerabilidad de ejecución remota de código en Remote Desktop Services (RDP). No requiere autenticación.',
        'remediation': 'Aplicar parche KB4499175. Deshabilitar RDP si no es necesario. Habilitar NLA.'
    },
    {
        'cve': 'CVE-2017-0143',
        'name': 'MS17-010 EternalBlue SMBv1 (variante)',
        'severity': 'critical',
        'cvss': 9.3,
        'description': 'Variante de EternalBlue afectando SMBv1 en Windows 7. Permite ejecución de código remoto sin autenticación.',
        'remediation': 'Aplicar MS17-010. Deshabilitar SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false'
    },
    {
        'cve': 'CVE-2012-0002',
        'name': 'MS12-020 RDP RCE (port 3389)',
        'severity': 'critical',
        'cvss': 9.3,
        'description': 'Vulnerabilidad de ejecución remota de código en Remote Desktop Protocol. Afecta Windows 7 sin parche.',
        'remediation': 'Aplicar MS12-020. Deshabilitar RDP o restringir acceso con firewall.'
    },
    {
        'cve': 'CVE-2014-6324',
        'name': 'MS14-068 Kerberos Privilege Escalation',
        'severity': 'critical',
        'cvss': 9.0,
        'description': 'Escalación de privilegios en implementación Kerberos. Permite a un usuario sin privilegios obtener acceso de Domain Admin.',
        'remediation': 'Aplicar parche MS14-068. Actualizar controladores de dominio.'
    },
    {
        'cve': 'CVE-2010-2568',
        'name': 'MS10-046 Windows Shell LNK RCE (Stuxnet)',
        'severity': 'critical',
        'cvss': 9.3,
        'description': 'Vulnerabilidad en Windows Shell al procesar archivos .LNK. Explotada por Stuxnet. Permite ejecución remota.',
        'remediation': 'Aplicar MS10-046. Deshabilitar la visualización de iconos de accesos directos.'
    },
    {
        'cve': 'CVE-2008-4250',
        'name': 'MS08-067 NetAPI RCE (Conficker)',
        'severity': 'critical',
        'cvss': 10.0,
        'description': 'Vulnerabilidad crítica en el servicio Windows Server (NetAPI). Explotada masivamente por el gusano Conficker.',
        'remediation': 'Aplicar MS08-067. Verificar si el sistema está infectado con Conficker.'
    },
    {
        'cve': 'CVE-2015-1635',
        'name': 'MS15-034 HTTP.sys RCE (IIS)',
        'severity': 'critical',
        'cvss': 10.0,
        'description': 'Vulnerabilidad en HTTP.sys de Windows. Permite ejecución remota de código si IIS está habilitado.',
        'remediation': 'Aplicar MS15-034. Si IIS no se usa, deshabilitar el servicio.'
    },
    {
        'cve': 'CVE-2020-0601',
        'name': 'CurveBall - Windows CryptoAPI Spoofing',
        'severity': 'high',
        'cvss': 8.1,
        'description': 'Vulnerabilidad en CryptoAPI (crypt32.dll) que permite falsificar certificados de código.',
        'remediation': 'Aplicar parche de enero 2020. Actualizar Windows Update.'
    },
    {
        'cve': 'CVE-2021-34527',
        'name': 'PrintNightmare - Print Spooler RCE',
        'severity': 'critical',
        'cvss': 8.8,
        'description': 'Vulnerabilidad en Windows Print Spooler. Permite ejecución remota de código y escalación de privilegios.',
        'remediation': 'Deshabilitar Print Spooler si no se usa. Aplicar parches KB5004945/KB5004946.'
    },
]

# CVEs específicos por servicio detectado
SERVICE_CVE_MAP = {
    'msrpc': [
        {'cve': 'CVE-2003-0352', 'name': 'DCOM RPC Buffer Overflow (Blaster)', 'severity': 'critical', 'cvss': 9.8},
    ],
    'netbios-ssn': [
        {'cve': 'CVE-2017-0145', 'name': 'MS17-010 EternalRomance SMB RCE', 'severity': 'critical', 'cvss': 8.1},
    ],
    'microsoft-ds': [
        {'cve': 'CVE-2020-0796', 'name': 'SMBGhost - SMBv3 RCE (Windows 10/Server 2019)', 'severity': 'critical', 'cvss': 10.0},
        {'cve': 'CVE-2017-0144', 'name': 'MS17-010 EternalBlue SMBv1 RCE', 'severity': 'critical', 'cvss': 9.8},
    ],
    'ms-wbt-server': [
        {'cve': 'CVE-2019-0708', 'name': 'BlueKeep RDP RCE sin autenticación', 'severity': 'critical', 'cvss': 9.8},
        {'cve': 'CVE-2019-1181', 'name': 'DejaBlue RDP RCE', 'severity': 'critical', 'cvss': 9.8},
        {'cve': 'CVE-2019-1182', 'name': 'DejaBlue RDP RCE (variante)', 'severity': 'critical', 'cvss': 9.8},
    ],
    'http': [
        {'cve': 'CVE-2015-1635', 'name': 'MS15-034 HTTP.sys RCE', 'severity': 'critical', 'cvss': 10.0},
    ],
}


class LANVulnScanner:
    """
    Escáner de vulnerabilidades para redes LAN
    Correlaciona OS y servicios detectados con CVEs conocidos de NVD
    """

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT = 15
    DELAY_BETWEEN_REQUESTS = 1  # segundos (rate limit NVD)

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'FAROSINT/1.0'})

    def scan(self, host_data: Dict[str, Any], target_ip: str) -> List[Dict]:
        """
        Ejecutar análisis completo de vulnerabilidades para un host LAN

        Args:
            host_data: Dict con datos del host (os, scripts, ports de Nmap)
            target_ip: IP del target

        Returns:
            Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []

        # 1. Vulnerabilidades basadas en OS
        os_info = host_data.get('os', {})
        os_vulns = self._get_os_vulnerabilities(os_info, target_ip)
        vulnerabilities.extend(os_vulns)
        print(f"  [LAN-Vuln] OS-based CVEs: {len(os_vulns)}")

        # 2. Vulnerabilidades basadas en servicios detectados
        ports = host_data.get('ports', [])
        service_vulns = self._get_service_vulnerabilities(ports, target_ip)
        # Evitar duplicados (ya pueden estar en os_vulns o NSE vulns)
        existing_cves = {v.get('cve') for v in vulnerabilities}
        for v in service_vulns:
            if v.get('cve') not in existing_cves:
                vulnerabilities.append(v)
                existing_cves.add(v.get('cve'))
        print(f"  [LAN-Vuln] Service-based CVEs adicionales: {len([v for v in service_vulns if v['cve'] not in existing_cves])}")

        return vulnerabilities

    def _get_os_vulnerabilities(self, os_info: Dict, target_ip: str) -> List[Dict]:
        """Buscar CVEs para el OS detectado"""
        if not os_info or not os_info.get('name'):
            return []

        os_name = os_info.get('name', '').lower()
        print(f"  [LAN-Vuln] OS detectado: {os_info.get('name')}")

        # Determinar CPE del OS
        cpe = self._detect_cpe_from_os(os_name, os_info)

        if not cpe:
            # Si no tenemos CPE, usar la lista hardcodeada para Windows 7
            if 'windows 7' in os_name:
                return self._format_known_vulns(WINDOWS7_KNOWN_CVES, target_ip)
            return []

        # Intentar NVD API
        # Consultar críticos + altos por separado para maximizar cobertura
        nvd_vulns = self._query_nvd_by_cpe(cpe, target_ip, severity_filter='CRITICAL')
        high_vulns = self._query_nvd_by_cpe(cpe, target_ip, severity_filter='HIGH', max_results=30)
        # Combinar evitando duplicados
        seen = {v['cve'] for v in nvd_vulns}
        for v in high_vulns:
            if v['cve'] not in seen:
                nvd_vulns.append(v)
                seen.add(v['cve'])
        if nvd_vulns:
            print(f"  [LAN-Vuln] NVD encontró {len(nvd_vulns)} CVEs para {cpe}")
            return nvd_vulns

        # Fallback: lista hardcodeada para Windows 7
        if 'windows 7' in os_name:
            print(f"  [LAN-Vuln] Usando lista conocida de CVEs para Windows 7")
            return self._format_known_vulns(WINDOWS7_KNOWN_CVES, target_ip)

        return []

    def _detect_cpe_from_os(self, os_name: str, os_info: Dict) -> str:
        """Detectar CPE a partir del nombre de OS"""
        for key, cpe in OS_CPE_MAP.items():
            if key in os_name:
                return cpe
        return ''

    def _query_nvd_by_cpe(self, cpe: str, target_ip: str, max_results: int = 50, severity_filter: str = 'CRITICAL') -> List[Dict]:
        """Consultar NVD API v2 por CPE"""
        try:
            params = {
                'cpeName': cpe,
                'resultsPerPage': max_results,
                'cvssV3Severity': severity_filter,
            }
            resp = self.session.get(
                self.NVD_API_URL,
                params=params,
                timeout=self.REQUEST_TIMEOUT
            )

            if resp.status_code != 200:
                print(f"  [LAN-Vuln] NVD API error: {resp.status_code}")
                return []

            data = resp.json()
            vulns = []

            for item in data.get('vulnerabilities', []):
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')

                # Descripción en inglés
                description = ''
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # CVSS Score (v3.1 preferido, luego v3.0, luego v2)
                cvss_score = 0.0
                severity = 'medium'
                metrics = cve_data.get('metrics', {})

                for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric_key in metrics and metrics[metric_key]:
                        m = metrics[metric_key][0]
                        cvss_data = m.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        # baseSeverity puede estar en la métrica o en cvssData
                        raw_sev = (m.get('baseSeverity') or
                                   cvss_data.get('baseSeverity', '')).upper()
                        if raw_sev:
                            severity = raw_sev.lower()
                        else:
                            # Calcular severidad desde score
                            if cvss_score >= 9.0:
                                severity = 'critical'
                            elif cvss_score >= 7.0:
                                severity = 'high'
                            elif cvss_score >= 4.0:
                                severity = 'medium'
                            else:
                                severity = 'low'
                        break

                # Solo incluir medium, high, critical
                if cvss_score < 4.0:
                    continue

                vulns.append({
                    'name': f'{cve_id} - {description[:80]}',
                    'severity': severity,
                    'host': target_ip,
                    'matched_at': target_ip,
                    'cve': cve_id,
                    'cvss_score': cvss_score,
                    'template': 'nvd-cpe-lookup',
                    'description': description,
                    'tags': ['nvd', 'cpe-lookup', 'windows'],
                    'references': {},
                    'remediation': {'steps': ['Aplicar parches de seguridad de Microsoft', 'Ver detalles en NVD']}
                })

            # Ordenar por CVSS score descendente
            vulns.sort(key=lambda x: x['cvss_score'], reverse=True)
            return vulns

        except requests.exceptions.ConnectionError:
            print(f"  [LAN-Vuln] Sin acceso a NVD API - usando fallback local")
            return []
        except Exception as e:
            print(f"  [LAN-Vuln] Error consultando NVD: {e}")
            return []

    def _get_service_vulnerabilities(self, ports: List[Dict], target_ip: str) -> List[Dict]:
        """Buscar CVEs basados en servicios detectados"""
        vulns = []
        seen_cves = set()

        for port in ports:
            service = port.get('service', '').lower()
            state = port.get('state', '')
            port_num = port.get('port', 0)

            if state not in ('open', 'filtered', 'open|filtered'):
                continue

            # Buscar en mapa de servicios
            if service in SERVICE_CVE_MAP:
                for cve_info in SERVICE_CVE_MAP[service]:
                    cve_id = cve_info.get('cve', '')
                    if cve_id and cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        vulns.append({
                            'name': cve_info.get('name', cve_id),
                            'severity': cve_info.get('severity', 'medium'),
                            'host': target_ip,
                            'matched_at': f"{target_ip}:{port_num}",
                            'cve': cve_id,
                            'cvss_score': cve_info.get('cvss', 5.0),
                            'template': f'service-{service}-cve',
                            'description': f'Servicio {service} en puerto {port_num} expuesto - {cve_info.get("name", "")}',
                            'tags': ['service', service, 'lan'],
                            'references': {},
                            'remediation': {'steps': [f'Aplicar parche para {cve_id}', f'Restringir acceso al puerto {port_num}']}
                        })

        return vulns

    def _format_known_vulns(self, known_vulns: List[Dict], target_ip: str) -> List[Dict]:
        """Formatear vulnerabilidades conocidas al formato estándar"""
        result = []
        for v in known_vulns:
            result.append({
                'name': v['name'],
                'severity': v['severity'],
                'host': target_ip,
                'matched_at': target_ip,
                'cve': v['cve'],
                'cvss_score': v['cvss'],
                'template': 'windows7-known-cve',
                'description': v.get('description', ''),
                'tags': ['windows', 'known-cve', 'lan'],
                'references': {},
                'remediation': {'steps': [v.get('remediation', 'Aplicar parches de seguridad')]}
            })
        return result
