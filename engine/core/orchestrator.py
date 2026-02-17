#!/usr/bin/env python3
"""
FAROSINT Orchestrator
Motor principal de orquestación OSINT
"""

import sys
import os
from pathlib import Path

# CRÍTICO: Agregar path del engine al PYTHONPATH ANTES de importar módulos locales
engine_path = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(engine_path))

import yaml
import threading
import time
from datetime import datetime

# Ahora sí importar los módulos locales
from core.cache_manager import CacheManager
from core.worker_pool import WorkerPool, TaskStatus
from core.task_queue import TaskQueueManager

# Importar módulos de herramientas
from modules.subfinder_module import SubfinderModule
from modules.amass_module import AmassModule
from modules.httpx_module import HttpxModule
from modules.nmap_module import NmapModule
from modules.nuclei_module import NucleiModule
from modules.rustscan_module import RustscanModule
from modules.whatweb_module import WhatWebModule
from modules.vuln_matcher_module import VulnMatcherModule
from modules.ip_reputation_module import IPReputationModule

# Nuevos módulos de herramientas
try:
    from modules.enum4linux_module import Enum4linuxModule
    _HAS_ENUM4LINUX = True
except ImportError:
    _HAS_ENUM4LINUX = False

try:
    from modules.nikto_module import NiktoModule
    _HAS_NIKTO = True
except ImportError:
    _HAS_NIKTO = False

try:
    from modules.gobuster_module import GobusterModule
    _HAS_GOBUSTER = True
except ImportError:
    _HAS_GOBUSTER = False

try:
    from modules.dnsrecon_module import DNSReconModule
    _HAS_DNSRECON = True
except ImportError:
    _HAS_DNSRECON = False

try:
    from modules.snmpwalk_module import SNMPModule
    _HAS_SNMP = True
except ImportError:
    _HAS_SNMP = False

# Importar utilidades de red
from modules.network_utils import detect_target_type, expand_target, nmap_ping_sweep

class FAROSINTOrchestrator:
    """Orquestador principal del motor OSINT"""

    def __init__(self, config_file=None, progress_callback=None):
        """
        Inicializar orquestador

        Args:
            config_file: Archivo de configuración YAML (opcional)
            progress_callback: Función para reportar progreso (opcional)
                              Firma: callback(phase, percent, message)
        """
        # Cargar configuración
        if config_file is None:
            config_file = Path.home() / "FAROSINT" / "engine" / "config.yaml"

        self.config = self._load_config(config_file)

        # Callback de progreso
        self.progress_callback = progress_callback

        # Inicializar componentes
        self.cache_manager = CacheManager(
            ttl=self.config['engine']['cache_ttl']
        ) if self.config['engine']['enable_cache'] else None

        self.worker_pool = WorkerPool(
            max_workers=self.config['engine']['max_workers']
        )

        self.task_queue = TaskQueueManager()

        # Directorio de salida
        self.output_dir = Path.home() / "FAROSINT" / "engine" / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # ID del escaneo actual
        self.scan_id = None
        self.scan_results = {}

        # Lock para thread-safety
        self.lock = threading.Lock()

        print(f"[Orchestrator] Inicializado con {self.config['engine']['max_workers']} workers")

    def _report_progress(self, phase, percent, message):
        """Reportar progreso via callback si está configurado"""
        if self.progress_callback:
            try:
                self.progress_callback(phase, percent, message)
            except Exception as e:
                print(f"[Orchestrator] Error en progress_callback: {e}")

    def _load_config(self, config_file):
        """Cargar archivo de configuración"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            print(f"[Orchestrator] Configuración cargada desde: {config_file}")
            return config
        except FileNotFoundError:
            print(f"[Orchestrator] Archivo de configuración no encontrado: {config_file}")
            print("[Orchestrator] Usando configuración por defecto")
            return self._default_config()

    def _default_config(self):
        """Configuración por defecto"""
        return {
            'engine': {
                'max_workers': 4,
                'default_timeout': 600,
                'enable_cache': True,
                'cache_ttl': 86400
            },
            'limits': {
                'max_subdomains': 500,
                'max_urls': 200,
                'max_ips': 100
            },
            'timeouts': {
                'subfinder': 300,
                'amass': 1800,
                'httpx': 600,
                'nmap_quick': 300,
                'nuclei': 1800
            },
            'priorities': {
                'subfinder': 1,
                'amass': 2,
                'httpx': 3,
                'nmap': 4,
                'nuclei': 5
            }
        }

    def scan(self, target, scan_type='full', **kwargs):
        """
        Iniciar escaneo completo

        Args:
            target: Dominio, IP, CIDR o rango objetivo
            scan_type: Tipo de escaneo ('quick', 'full', 'custom', 'lan')
            **kwargs: Parámetros adicionales

        Returns:
            Dict con resultados del escaneo
        """
        # Guardar target como atributo de instancia
        self.target = target

        # Detectar tipo de target
        target_type = detect_target_type(target)

        # Generar ID de escaneo
        scan_id_clean = target.replace('/', '_').replace('.', '_').replace(':', '_')
        self.scan_id = f"{scan_id_clean}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        print(f"\n{'='*60}")
        print(f"  FAROSINT - Análisis de Superficie de Ataque")
        print(f"{'='*60}")
        print(f"Objetivo: {target}")
        print(f"Tipo de Target: {target_type}")
        print(f"Tipo de Escaneo: {scan_type}")
        print(f"Scan ID: {self.scan_id}")
        print(f"{'='*60}\n")

        # Limpiar resultados previos
        self.scan_results = {
            'target': target,
            'target_type': target_type,
            'scan_id': self.scan_id,
            'scan_type': scan_type,
            'start_time': datetime.now().isoformat(),
            'subdomains': [],
            'alive_urls': [],
            'hosts': [],
            'ports': {},
            'vulnerabilities': []
        }

        # Reportar inicio inmediatamente (para que la barra de progreso aparezca)
        self._report_progress("Inicializando", 0, f"Preparando escaneo {scan_type} para {target}")

        # Definir pipeline según tipo de escaneo o tipo de target
        # Si el target es IP/CIDR, forzar modo LAN independientemente del scan_type
        if target_type in ['ip', 'cidr', 'range'] or scan_type == 'lan':
            self._run_lan_scan(target)
        elif scan_type == 'quick':
            self._run_quick_scan(target)
        elif scan_type == 'full':
            self._run_full_scan(target)
        else:
            self._run_custom_scan(target, **kwargs)

        # Esperar a que terminen todas las tareas
        self.worker_pool.wait_all()

        # Recopilar resultados
        self._collect_results()

        # Guardar resultados
        self._save_results()

        # Finalizar
        self.scan_results['end_time'] = datetime.now().isoformat()

        # Reportar finalización
        total_vulns = len(self.scan_results.get('vulnerabilities', []))
        total_ports = sum(
            len(host.get('ports', []))
            for port_data in self.scan_results.get('ports', {}).values()
            for host in (port_data.get('hosts', []) if isinstance(port_data, dict) else [])
        )
        self._report_progress("Completado", 100,
            f"Escaneo finalizado: {total_ports} puertos, {total_vulns} vulnerabilidades")

        print(f"\n{'='*60}")
        print(f"  ESCANEO COMPLETADO")
        print(f"{'='*60}")
        self._print_summary()

        return self.scan_results

    def _run_quick_scan(self, target):
        """
        Escaneo rápido (5-15 minutos)
        - Subfinder (rápido)
        - Httpx
        - Nmap quick (top 100 ports)
        """
        print("[Pipeline] Modo RÁPIDO iniciado\n")
        self._report_progress("Inicio", 5, "Iniciando escaneo rápido")

        # Fase 1: Subfinder (alta prioridad)
        subfinder_task = self.worker_pool.submit(
            name="Subfinder",
            function=self._run_subfinder,
            args=[target],
            timeout=self.config['timeouts']['subfinder'],
            priority=self.config['priorities']['subfinder']
        )

        # Esperar a Subfinder
        self.worker_pool.wait_all()

        # Obtener subdominios (resiliente a fallos)
        subdomains = []
        subfinder_result = self.worker_pool.get_result(subfinder_task)
        if subfinder_result:
            if subfinder_result.status == TaskStatus.COMPLETED and subfinder_result.result:
                subdomains = subfinder_result.result
                print(f"\n  ✓ Subfinder: {len(subdomains)} subdominios")
            elif subfinder_result.status == TaskStatus.TIMEOUT:
                print(f"\n  ⏱ Subfinder: Timeout después de {subfinder_result.timeout}s (continuando)")
            elif subfinder_result.status == TaskStatus.FAILED:
                print(f"\n  ✗ Subfinder: Error - {subfinder_result.error} (continuando)")

        # Aplicar límites
        if len(subdomains) > self.config['limits']['max_subdomains']:
            print(f"[Pipeline] Limitando a {self.config['limits']['max_subdomains']} subdominios")
            subdomains = self._prioritize_subdomains(subdomains)

        self.scan_results['subdomains'] = subdomains
        self._report_progress("Enumeración", 30, f"Encontrados {len(subdomains)} subdominios")

        # Fase 1b: DNSRecon (paralelo con fase 2)
        if _HAS_DNSRECON:
            self.worker_pool.submit(
                name="DNSRecon",
                function=self._run_dnsrecon,
                args=[target],
                timeout=120,
                priority=3
            )

        # Fase 2: Httpx
        # IMPORTANTE: Agregar siempre el dominio principal a la lista
        # Incluso si Subfinder falló, continuamos con el dominio principal
        hosts_to_check = [self.target] + subdomains
        hosts_to_check = list(dict.fromkeys(hosts_to_check))

        print(f"\n[Fase 2] Verificando {len(hosts_to_check)} hosts con Httpx")
        self._report_progress("Verificación Web", 40, f"Verificando {len(hosts_to_check)} hosts con Httpx")

        httpx_task = self.worker_pool.submit(
            name="Httpx",
            function=self._run_httpx,
            args=[hosts_to_check],
            timeout=self.config['timeouts']['httpx'],
            priority=self.config['priorities']['httpx']
        )

        # Esperar a Httpx
        self.worker_pool.wait_all()

        # Obtener URLs activas (resiliente a fallos)
        alive_urls = []
        httpx_result = self.worker_pool.get_result(httpx_task)
        if httpx_result:
            if httpx_result.status == TaskStatus.COMPLETED and httpx_result.result:
                alive_urls = httpx_result.result
                print(f"  ✓ Httpx: {len(alive_urls)} URLs activas")
            elif httpx_result.status == TaskStatus.TIMEOUT:
                print(f"  ⏱ Httpx: Timeout después de {httpx_result.timeout}s (continuando)")
            elif httpx_result.status == TaskStatus.FAILED:
                print(f"  ✗ Httpx: Error - {httpx_result.error} (continuando)")

        self.scan_results['alive_urls'] = alive_urls
        self._report_progress("Verificación Web", 55, f"Encontradas {len(alive_urls)} URLs activas")

        # Fase 3: Nmap quick (solo si hay URLs activas)
        if alive_urls:
            # Filtrar CDN/WAF y deduplicar por IP
            nmap_targets, cdn_hosts, ip_to_hostnames = self._filter_nmap_targets(alive_urls)

            # Guardar info CDN en resultados
            if cdn_hosts:
                self.scan_results['cdn_hosts'] = cdn_hosts

            if len(nmap_targets) > self.config['limits']['max_ips']:
                print(f"[Pipeline] Limitando a {self.config['limits']['max_ips']} hosts para Nmap")
                nmap_targets = nmap_targets[:self.config['limits']['max_ips']]

            if nmap_targets:
                print(f"\n[Fase 3] Escaneando {len(nmap_targets)} hosts con Nmap (quick)")
                self._report_progress("Escaneo de Puertos", 65, f"Escaneando {len(nmap_targets)} hosts con Nmap")

                for target_host in nmap_targets:
                    self.worker_pool.submit(
                        name=f"Nmap-{target_host}",
                        function=self._run_nmap,
                        args=[target_host],
                        kwargs={'scan_type': 'quick'},
                        timeout=self.config['timeouts']['nmap_quick'],
                        priority=self.config['priorities']['nmap']
                    )
            else:
                print("[Pipeline] Todos los hosts son CDN/WAF - omitiendo Nmap")

            # Nikto y Gobuster en las URLs activas
            self.worker_pool.wait_all()
            self._report_progress("Escaneo Web", 80, "Analizando servicios web con Nikto y Gobuster")
            for url in alive_urls[:5]:  # Limitar a 5 URLs para no demorar demasiado
                url_str = url.get('url', '') if isinstance(url, dict) else str(url)
                if url_str and _HAS_NIKTO:
                    self.worker_pool.submit(
                        name=f"Nikto-{url_str}",
                        function=self._run_nikto,
                        args=[url_str],
                        timeout=180,
                        priority=5
                    )
                if url_str and _HAS_GOBUSTER:
                    self.worker_pool.submit(
                        name=f"Gobuster-{url_str}",
                        function=self._run_gobuster,
                        args=[url_str],
                        timeout=120,
                        priority=5
                    )
            self.worker_pool.wait_all()
        else:
            print("[Pipeline] No hay URLs activas - omitiendo escaneo de puertos")
            self._report_progress("Finalizado", 100, "Escaneo rápido completado")

    def _run_full_scan(self, target):
        """
        Escaneo completo (30-90 minutos)
        - Subfinder + Amass (paralelo)
        - Httpx
        - Nmap full (top 1000 ports)
        - Nuclei
        """
        print("[Pipeline] Modo COMPLETO iniciado\n")
        self._report_progress("Inicio", 0, "Iniciando escaneo completo")

        # Fase 1: Subfinder + Amass en paralelo
        print("[Fase 1] Enumeración de subdominios (paralelo)")
        self._report_progress("Enumeración", 10, "Buscando subdominios con Subfinder y Amass")

        subfinder_task = self.worker_pool.submit(
            name="Subfinder",
            function=self._run_subfinder,
            args=[target],
            timeout=self.config['timeouts']['subfinder'],
            priority=self.config['priorities']['subfinder']
        )

        amass_task = self.worker_pool.submit(
            name="Amass",
            function=self._run_amass,
            args=[target],
            timeout=self.config['timeouts']['amass'],
            priority=self.config['priorities']['amass']
        )

        # Esperar a ambos
        self.worker_pool.wait_all()

        # Combinar resultados (resiliente a fallos individuales)
        subdomains = set()

        subfinder_result = self.worker_pool.get_result(subfinder_task)
        if subfinder_result:
            if subfinder_result.status == TaskStatus.COMPLETED and subfinder_result.result:
                subdomains.update(subfinder_result.result)
                print(f"  ✓ Subfinder: {len(subfinder_result.result)} subdominios")
            elif subfinder_result.status == TaskStatus.TIMEOUT:
                print(f"  ⏱ Subfinder: Timeout después de {subfinder_result.timeout}s (continuando)")
            elif subfinder_result.status == TaskStatus.FAILED:
                print(f"  ✗ Subfinder: Error - {subfinder_result.error} (continuando)")

        amass_result = self.worker_pool.get_result(amass_task)
        if amass_result:
            if amass_result.status == TaskStatus.COMPLETED and amass_result.result:
                subdomains.update(amass_result.result)
                print(f"  ✓ Amass: {len(amass_result.result)} subdominios")
            elif amass_result.status == TaskStatus.TIMEOUT:
                print(f"  ⏱ Amass: Timeout después de {amass_result.timeout}s (continuando)")
            elif amass_result.status == TaskStatus.FAILED:
                print(f"  ✗ Amass: Error - {amass_result.error} (continuando)")

        subdomains = list(subdomains)
        print(f"\n[Pipeline] Total único: {len(subdomains)} subdominios")
        self._report_progress("Enumeración", 30, f"Encontrados {len(subdomains)} subdominios")

        # Aplicar límites
        if len(subdomains) > self.config['limits']['max_subdomains']:
            print(f"[Pipeline] Limitando a {self.config['limits']['max_subdomains']} subdominios")
            subdomains = self._prioritize_subdomains(subdomains)

        self.scan_results['subdomains'] = subdomains

        # Fase 2: Httpx
        print("\n[Fase 2] Verificación de servicios web")

        # IMPORTANTE: Agregar siempre el dominio principal a la lista de hosts
        # Incluso si no se encontraron subdominios, continuamos con el dominio principal
        hosts_to_check = [self.target] + subdomains
        # Eliminar duplicados manteniendo orden
        hosts_to_check = list(dict.fromkeys(hosts_to_check))

        print(f"[Pipeline] Verificando {len(hosts_to_check)} hosts (incluyendo dominio principal)")

        self._report_progress("Verificación Web", 40, f"Verificando {len(hosts_to_check)} hosts con Httpx")

        httpx_task = self.worker_pool.submit(
            name="Httpx",
            function=self._run_httpx,
            args=[hosts_to_check],
            timeout=self.config['timeouts']['httpx'],
            priority=self.config['priorities']['httpx']
        )

        self.worker_pool.wait_all()

        httpx_result = self.worker_pool.get_result(httpx_task)
        alive_urls = []

        if httpx_result:
            if httpx_result.status == TaskStatus.COMPLETED and httpx_result.result:
                alive_urls = httpx_result.result
                print(f"  ✓ Httpx: {len(alive_urls)} URLs activas")
                self._report_progress("Verificación Web", 50, f"Encontradas {len(alive_urls)} URLs activas")
            elif httpx_result.status == TaskStatus.TIMEOUT:
                print(f"  ⏱ Httpx: Timeout después de {httpx_result.timeout}s (continuando)")
                self._report_progress("Verificación Web", 50, "Httpx timeout - continuando sin URLs activas")
            elif httpx_result.status == TaskStatus.FAILED:
                print(f"  ✗ Httpx: Error - {httpx_result.error} (continuando)")
                self._report_progress("Verificación Web", 50, "Httpx falló - continuando sin URLs activas")

        self.scan_results['alive_urls'] = alive_urls

        # Fase 1b: DNSRecon en paralelo con Httpx (ya terminó Fase 2)
        if _HAS_DNSRECON:
            self.worker_pool.submit(
                name="DNSRecon",
                function=self._run_dnsrecon,
                args=[target],
                timeout=120,
                priority=3
            )

        # Fase 3: Nmap full (solo si hay URLs activas)
        if alive_urls:
            # Filtrar CDN/WAF y deduplicar por IP
            nmap_targets, cdn_hosts, ip_to_hostnames = self._filter_nmap_targets(alive_urls)

            # Guardar info CDN en resultados
            if cdn_hosts:
                self.scan_results['cdn_hosts'] = cdn_hosts

            if len(nmap_targets) > self.config['limits']['max_ips']:
                print(f"[Pipeline] Limitando a {self.config['limits']['max_ips']} hosts para Nmap")
                nmap_targets = nmap_targets[:self.config['limits']['max_ips']]

            if nmap_targets:
                print(f"\n[Fase 3] Escaneo de puertos ({len(nmap_targets)} hosts, excluidos {len(cdn_hosts)} CDN/WAF)")
                self._report_progress("Escaneo de Puertos", 60, f"Escaneando {len(nmap_targets)} hosts con Nmap")

                for target_host in nmap_targets:
                    self.worker_pool.submit(
                        name=f"Nmap-{target_host}",
                        function=self._run_nmap,
                        args=[target_host],
                        kwargs={'scan_type': 'full'},
                        timeout=self.config['timeouts'].get('nmap_full', 1800),
                        priority=self.config['priorities']['nmap']
                    )
            else:
                print("[Pipeline] Todos los hosts son CDN/WAF - omitiendo Nmap")

            self.worker_pool.wait_all()
            self._report_progress("Escaneo de Puertos", 75, "Escaneo de puertos completado")

            # Fase 4: Nuclei + Nikto + Gobuster en URLs activas (paralelo)
            print(f"\n[Fase 4] Detección de vulnerabilidades web")

            # Extraer URLs
            target_urls = [url.get('url') for url in alive_urls if url.get('url')]

            if len(target_urls) > self.config['limits']['max_urls']:
                print(f"[Pipeline] Limitando a {self.config['limits']['max_urls']} URLs para análisis")
                target_urls = target_urls[:self.config['limits']['max_urls']]

            if target_urls:
                self._report_progress("Vulnerabilidades", 80, f"Escaneando {len(target_urls)} URLs con Nuclei, Nikto y Gobuster")

                # Nuclei (todas las URLs)
                self.worker_pool.submit(
                    name="Nuclei",
                    function=self._run_nuclei,
                    args=[target_urls],
                    timeout=self.config['timeouts']['nuclei'],
                    priority=self.config['priorities']['nuclei']
                )

                # Nikto (hasta 10 URLs en full scan)
                if _HAS_NIKTO:
                    for url_str in target_urls[:10]:
                        self.worker_pool.submit(
                            name=f"Nikto-{url_str}",
                            function=self._run_nikto,
                            args=[url_str],
                            timeout=300,
                            priority=5
                        )

                # Gobuster (hasta 10 URLs en full scan)
                if _HAS_GOBUSTER:
                    for url_str in target_urls[:10]:
                        self.worker_pool.submit(
                            name=f"Gobuster-{url_str}",
                            function=self._run_gobuster,
                            args=[url_str],
                            timeout=180,
                            priority=5
                        )

                self.worker_pool.wait_all()
                self._report_progress("Vulnerabilidades", 100, "Análisis de vulnerabilidades completado")
            else:
                print("[Pipeline] No hay URLs para escanear con Nuclei/Nikto/Gobuster")
                self._report_progress("Vulnerabilidades", 100, "Sin URLs para escanear vulnerabilidades")
        else:
            print("[Pipeline] No hay URLs activas - omitiendo escaneo de puertos y vulnerabilidades")
            self._report_progress("Escaneo de Puertos", 100, "Sin URLs activas - fases restantes omitidas")

    def _run_custom_scan(self, target, **kwargs):
        """Escaneo personalizado según parámetros"""
        print("[Pipeline] Modo PERSONALIZADO iniciado\n")
        # Implementar lógica personalizada según kwargs
        pass

    def _run_lan_scan(self, target):
        """
        Escaneo de red LAN
        - Host Discovery (Nmap ping sweep)
        - Port Scanning en hosts vivos
        - Service Detection
        - Nuclei para servicios web
        """
        print("[Pipeline] Modo LAN/NETWORK iniciado\n")
        self._report_progress("Host Discovery", 5, "Expandiendo target y detectando hosts vivos")

        # Expandir target (IP, CIDR, rango)
        try:
            max_hosts = self.config['limits'].get('max_lan_hosts', 254)
            target_type, host_list = expand_target(target, max_hosts=max_hosts)

            print(f"[Fase 1] Target expandido: {len(host_list)} hosts potenciales")

        except ValueError as e:
            print(f"[!] Error expandiendo target: {e}")
            self._report_progress("Error", 0, str(e))
            return

        # Fase 1: Host Discovery con Nmap ping sweep
        print(f"[Fase 1] Host Discovery - Ping sweep en {len(host_list)} hosts")
        self._report_progress("Host Discovery", 10, f"Buscando hosts vivos en {len(host_list)} direcciones")

        try:
            # Si es un solo host, no hacer ping sweep
            if len(host_list) == 1:
                alive_hosts = host_list
                print(f"  ℹ Target único, omitiendo ping sweep")
            else:
                timeout = self.config['timeouts'].get('host_discovery', 300)
                alive_hosts = nmap_ping_sweep(host_list, timeout=timeout)
                print(f"  ✓ Hosts vivos: {len(alive_hosts)}/{len(host_list)}")

            if not alive_hosts:
                print("[!] No se encontraron hosts vivos")
                self._report_progress("Host Discovery", 100, "No se encontraron hosts vivos")
                return

            self.scan_results['hosts'] = alive_hosts
            self._report_progress("Host Discovery", 30, f"Encontrados {len(alive_hosts)} hosts vivos")

        except Exception as e:
            print(f"[!] Error en host discovery: {e}")
            self._report_progress("Error", 30, f"Host discovery falló: {str(e)}")
            # Continuar con todos los hosts
            alive_hosts = host_list
            self.scan_results['hosts'] = alive_hosts

        # Aplicar límites
        max_ips = self.config['limits'].get('max_ips', 100)
        if len(alive_hosts) > max_ips:
            print(f"[Pipeline] Limitando a {max_ips} hosts para escaneo de puertos")
            alive_hosts = alive_hosts[:max_ips]

        # Fase 2: Port Scanning con Nmap
        print(f"\n[Fase 2] Port Scanning - Escaneando {len(alive_hosts)} hosts")
        self._report_progress("Port Scanning", 40, f"Escaneando puertos en {len(alive_hosts)} hosts")

        # Determinar tipo de escaneo según número de hosts
        if len(alive_hosts) <= 5:
            scan_mode = 'full'  # Top 1000 puertos
            timeout_key = 'nmap_full'
        else:
            scan_mode = 'quick'  # Top 100 puertos
            timeout_key = 'nmap_quick'

        print(f"  Modo: {scan_mode} ({len(alive_hosts)} hosts)")

        for ip in alive_hosts:
            self.worker_pool.submit(
                name=f"Nmap-{ip}",
                function=self._run_nmap,
                args=[ip],
                kwargs={'scan_type': scan_mode},
                timeout=self.config['timeouts'].get(timeout_key, 600),
                priority=self.config['priorities'].get('nmap', 4)
            )

        # Esperar a que terminen los escaneos de puertos
        self.worker_pool.wait_all()
        self._report_progress("Port Scanning", 70, "Escaneo de puertos completado")

        # Fase 3: Identificar servicios web
        print(f"\n[Fase 3] Service Detection - Identificando servicios web")
        self._report_progress("Service Detection", 75, "Identificando servicios web")

        web_targets = []

        # Analizar resultados de Nmap para encontrar servicios web
        for ip, port_info in self.scan_results.get('ports', {}).items():
            if not port_info or not port_info.get('ports'):
                continue

            for port_data in port_info.get('ports', []):
                port = port_data.get('port')
                service = port_data.get('service', '').lower()

                # Detectar servicios web
                if service in ['http', 'https', 'http-alt', 'http-proxy', 'ssl/http'] or \
                   port in [80, 443, 8000, 8080, 8443, 8888, 3000]:

                    # Determinar protocolo
                    if port == 443 or port == 8443 or 'https' in service or 'ssl' in service:
                        protocol = 'https'
                    else:
                        protocol = 'http'

                    url = f"{protocol}://{ip}:{port}"
                    web_targets.append(url)

        if web_targets:
            print(f"  ✓ Servicios web encontrados: {len(web_targets)}")

            # Aplicar límites
            max_urls = self.config['limits'].get('max_urls', 200)
            if len(web_targets) > max_urls:
                print(f"[Pipeline] Limitando a {max_urls} URLs para Nuclei")
                web_targets = web_targets[:max_urls]

            # Fase 4: Nuclei para detección de vulnerabilidades
            print(f"\n[Fase 4] Vulnerability Scanning - Escaneando {len(web_targets)} servicios web")
            self._report_progress("Vulnerabilidades", 80, f"Escaneando {len(web_targets)} servicios con Nuclei")

            nuclei_task = self.worker_pool.submit(
                name="Nuclei-LAN",
                function=self._run_nuclei,
                args=[web_targets],
                timeout=self.config['timeouts'].get('nuclei', 1800),
                priority=self.config['priorities'].get('nuclei', 5)
            )

            self.worker_pool.wait_all()
            self._report_progress("Vulnerabilidades", 95, "Escaneo de vulnerabilidades completado")
        else:
            print("  ℹ No se encontraron servicios web")
            self._report_progress("Vulnerabilidades", 95, "No se encontraron servicios web")

        # Fase 5: enum4linux-ng para Windows (si hay SMB abierto)
        smb_hosts = []
        for ip, port_data in self.scan_results.get('ports', {}).items():
            for host in port_data.get('hosts', []):
                for port in host.get('ports', []):
                    if port.get('port') in (139, 445) and port.get('state') == 'open':
                        if ip not in smb_hosts:
                            smb_hosts.append(ip)
        if smb_hosts and _HAS_ENUM4LINUX:
            print(f"\n[Fase 5] Enum4linux-ng - Enumerando {len(smb_hosts)} hosts Windows")
            self._report_progress("Enumeración SMB", 85, f"Enumerando usuarios/shares en {len(smb_hosts)} hosts")
            for ip in smb_hosts:
                self.worker_pool.submit(
                    name=f"Enum4linux-{ip}",
                    function=self._run_enum4linux,
                    args=[ip],
                    timeout=120,
                    priority=4
                )
            self.worker_pool.wait_all()

        # Fase 6: SNMP si hay puerto 161 abierto
        snmp_hosts = []
        for ip, port_data in self.scan_results.get('ports', {}).items():
            for host in port_data.get('hosts', []):
                for port in host.get('ports', []):
                    if port.get('port') == 161 and port.get('state') in ('open', 'open|filtered'):
                        if ip not in snmp_hosts:
                            snmp_hosts.append(ip)
        if snmp_hosts and _HAS_SNMP:
            print(f"\n[Fase 6] SNMP - Enumerando {len(snmp_hosts)} hosts")
            self._report_progress("SNMP", 90, f"Enumerando SNMP en {len(snmp_hosts)} hosts")
            for ip in snmp_hosts:
                self.worker_pool.submit(
                    name=f"SNMP-{ip}",
                    function=self._run_snmp,
                    args=[ip],
                    timeout=60,
                    priority=4
                )
            self.worker_pool.wait_all()

        # Fase 7: CVE lookup basado en OS y servicios detectados
        print(f"\n[Fase 7] CVE Lookup - Buscando vulnerabilidades por OS y servicios")
        self._report_progress("CVE Lookup", 95, "Buscando CVEs conocidos para OS y servicios detectados")
        self._run_lan_cve_lookup()

        print(f"\n[Pipeline] Escaneo LAN completado")
        self._report_progress("Finalizado", 100, "Escaneo LAN completado")

    def _run_enum4linux(self, target):
        """Ejecutar enum4linux-ng para enumeración SMB/Windows"""
        if not _HAS_ENUM4LINUX:
            return {}
        module = Enum4linuxModule(timeout=120, cache_manager=self.cache_manager)
        result = module.run(target)

        with self.lock:
            # Guardar en raw_results para mostrar en UI
            if 'enum4linux' not in self.scan_results:
                self.scan_results['enum4linux'] = {}
            self.scan_results['enum4linux'][target] = result

            # Si no hay usuarios/shares en smb_info, al menos loguear
            users = result.get('users', [])
            shares = result.get('shares', [])
            print(f"  [Enum4linux-{target}] {len(users)} usuarios, {len(shares)} shares")

            # Agregar vuln si hay shares con acceso anónimo
            for share in shares:
                if 'read' in share.get('access', '').lower() or 'anonymous' in str(share).lower():
                    self.scan_results['vulnerabilities'].append({
                        'name': f'SMB Share accesible sin autenticación: {share["name"]}',
                        'severity': 'high',
                        'host': target,
                        'matched_at': f'{target}\\{share["name"]}',
                        'cve': None,
                        'cvss_score': 7.5,
                        'template': 'smb-anonymous-share',
                        'description': f'El share SMB \\\\{target}\\{share["name"]} es accesible anónimamente.',
                        'tags': ['smb', 'anonymous', 'lan'],
                        'references': {},
                        'remediation': {'steps': ['Deshabilitar acceso anónimo a shares SMB', 'Revisar permisos de shares en Windows']}
                    })
        return result

    def _run_snmp(self, target):
        """Ejecutar enumeración SNMP"""
        if not _HAS_SNMP:
            return {}
        module = SNMPModule(timeout=60, cache_manager=self.cache_manager)
        result = module.run(target)

        with self.lock:
            if 'snmp' not in self.scan_results:
                self.scan_results['snmp'] = {}
            self.scan_results['snmp'][target] = result

            # Agregar vulnerabilidad si community es por defecto
            vuln = result.get('vulnerability')
            if vuln:
                self.scan_results['vulnerabilities'].append({
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'host': target,
                    'matched_at': f'{target}:161',
                    'cve': vuln.get('cve'),
                    'cvss_score': vuln.get('cvss', 5.0),
                    'template': 'snmp-default-community',
                    'description': vuln['description'],
                    'tags': ['snmp', 'lan', 'default-credentials'],
                    'references': {},
                    'remediation': {'steps': ['Cambiar community string por defecto', 'Restringir acceso SNMP por IP', 'Usar SNMPv3 con autenticación']}
                })
        return result

    def _run_nikto(self, target_url):
        """Ejecutar Nikto para vulnerabilidades web"""
        if not _HAS_NIKTO:
            return []
        module = NiktoModule(timeout=180, cache_manager=self.cache_manager)
        findings = module.run(target_url)

        with self.lock:
            self.scan_results['vulnerabilities'].extend(findings)
            print(f"  [Nikto-{target_url}] {len(findings)} findings")
        return findings

    def _run_gobuster(self, target_url):
        """Ejecutar Gobuster para enumeración de directorios"""
        if not _HAS_GOBUSTER:
            return []
        module = GobusterModule(timeout=120, cache_manager=self.cache_manager)
        findings = module.run(target_url)

        with self.lock:
            # Solo guardar findings de severidad medium/high como vulnerabilidades
            high_findings = [f for f in findings if f.get('severity') in ('high', 'medium')]
            self.scan_results['vulnerabilities'].extend(high_findings)
            # Guardar todos en raw_results
            if 'gobuster' not in self.scan_results:
                self.scan_results['gobuster'] = {}
            self.scan_results['gobuster'][target_url] = findings
            print(f"  [Gobuster-{target_url}] {len(findings)} paths ({len(high_findings)} relevantes)")
        return findings

    def _run_dnsrecon(self, domain):
        """Ejecutar dnsrecon para reconocimiento DNS"""
        if not _HAS_DNSRECON:
            return {}
        module = DNSReconModule(timeout=120, cache_manager=self.cache_manager)
        result = module.run(domain)

        with self.lock:
            self.scan_results['dns_recon'] = result
            # Agregar subdominios encontrados
            new_subs = result.get('subdomains', [])
            existing = set(self.scan_results.get('subdomains', []))
            for sub in new_subs:
                if sub not in existing:
                    self.scan_results['subdomains'].append(sub)
                    existing.add(sub)
            # Zone transfer = vulnerabilidad crítica
            if result.get('zone_transfer'):
                self.scan_results['vulnerabilities'].append({
                    'name': f'DNS Zone Transfer habilitado en {domain}',
                    'severity': 'high',
                    'host': domain,
                    'matched_at': domain,
                    'cve': 'CVE-1999-0532',
                    'cvss_score': 5.0,
                    'template': 'dns-zone-transfer',
                    'description': f'El servidor DNS de {domain} permite Zone Transfer (AXFR), exponiendo todos los registros DNS.',
                    'tags': ['dns', 'zone-transfer'],
                    'references': {},
                    'remediation': {'steps': ['Restringir Zone Transfer solo a servidores NS secundarios autorizados']}
                })
            print(f"  [DNSRecon-{domain}] {len(result.get('a_records',[]))} A, {len(result.get('mx_records',[]))} MX, zone_transfer={result.get('zone_transfer')}")
        return result

    def _run_lan_cve_lookup(self):
        """
        Buscar CVEs para OS y servicios detectados en escaneo LAN
        Usa NVD API + lista de CVEs conocidos de Windows
        """
        try:
            from modules.lan_vuln_scanner import LANVulnScanner
            scanner = LANVulnScanner()

            for ip, port_data in self.scan_results.get('ports', {}).items():
                hosts = port_data.get('hosts', []) if isinstance(port_data, dict) else []
                for host in hosts:
                    print(f"  [CVE-Lookup] Analizando {ip}...")
                    vulns = scanner.scan(host, ip)

                    # Evitar duplicados con vulns ya detectadas por NSE
                    existing_cves = {v.get('cve') for v in self.scan_results.get('vulnerabilities', [])}
                    new_vulns = [v for v in vulns if v.get('cve') not in existing_cves]

                    with self.lock:
                        self.scan_results['vulnerabilities'].extend(new_vulns)

                    print(f"  [CVE-Lookup] {len(new_vulns)} CVEs nuevos agregados para {ip}")

        except Exception as e:
            print(f"  [CVE-Lookup] Error: {e}")
            import traceback
            traceback.print_exc()

    # =============================
    # Funciones de ejecución de módulos
    # =============================

    def _run_subfinder(self, domain):
        """Ejecutar Subfinder"""
        module = SubfinderModule(
            timeout=self.config['timeouts']['subfinder'],
            cache_manager=self.cache_manager
        )
        return module.run(domain)

    def _run_amass(self, domain):
        """Ejecutar Amass"""
        module = AmassModule(
            timeout=self.config['timeouts']['amass'],
            cache_manager=self.cache_manager
        )
        return module.run(domain, mode='passive')

    def _run_httpx(self, hosts):
        """Ejecutar Httpx"""
        module = HttpxModule(
            timeout=self.config['timeouts']['httpx'],
            cache_manager=self.cache_manager
        )
        return module.run(hosts)

    def _run_nmap(self, target, scan_type='quick'):
        """Ejecutar Nmap"""
        module = NmapModule(
            timeout=self.config['timeouts'].get(f'nmap_{scan_type}', 600),
            cache_manager=self.cache_manager
        )
        result = module.run(target, scan_type=scan_type)

        # Guardar en resultados globales
        with self.lock:
            self.scan_results['ports'][target] = result

            # Guardar vulnerabilidades NSE detectadas por scripts de Nmap
            nse_vulns = result.get('nse_vulnerabilities', [])
            if nse_vulns:
                self.scan_results['vulnerabilities'].extend(nse_vulns)
                print(f"  [Nmap-{target}] {len(nse_vulns)} vulnerabilidades NSE detectadas")

        return result

    def _run_nuclei(self, targets):
        """Ejecutar Nuclei"""
        module = NucleiModule(
            timeout=self.config['timeouts']['nuclei'],
            cache_manager=self.cache_manager
        )
        vulns = module.run(targets)

        # Guardar en resultados globales
        with self.lock:
            self.scan_results['vulnerabilities'].extend(vulns)

        return vulns

    def _run_rustscan(self, target):
        """Ejecutar Rustscan para descubrimiento rápido de puertos"""
        module = RustscanModule(
            timeout=self.config['timeouts'].get('rustscan', 300),
            cache_manager=self.cache_manager
        )
        return module.run(target)

    def _run_whatweb(self, urls):
        """Ejecutar WhatWeb para identificación de tecnologías"""
        module = WhatWebModule(
            timeout=self.config['timeouts'].get('whatweb', 600),
            cache_manager=self.cache_manager
        )
        results = module.run(urls)

        # Guardar en resultados globales
        with self.lock:
            if 'technologies' not in self.scan_results:
                self.scan_results['technologies'] = []
            self.scan_results['technologies'].extend(results.get('urls', []))

        return results

    def _run_vuln_matcher(self, services):
        """Ejecutar Vulnerability Matcher para correlación con CVEs"""
        module = VulnMatcherModule(
            timeout=self.config['timeouts'].get('vuln_matcher', 300),
            cache_manager=self.cache_manager
        )
        results = module.run(services)

        # Guardar en resultados globales
        with self.lock:
            if 'cve_matches' not in self.scan_results:
                self.scan_results['cve_matches'] = []
            self.scan_results['cve_matches'].extend(results.get('services', []))

        return results

    def _run_ip_reputation(self, ips):
        """Ejecutar IP Reputation check"""
        module = IPReputationModule(
            timeout=self.config['timeouts'].get('ip_reputation', 300),
            cache_manager=self.cache_manager
        )
        results = module.run(ips)

        # Guardar en resultados globales
        with self.lock:
            if 'ip_reputation' not in self.scan_results:
                self.scan_results['ip_reputation'] = []
            self.scan_results['ip_reputation'].extend(results.get('ips', []))

        return results

    # =============================
    # Utilidades
    # =============================

    def _filter_nmap_targets(self, alive_urls):
        """
        Filtrar targets para Nmap: excluir CDN/WAF y deduplicar por IP.

        Los hosts detrás de CDN/WAF (ej. Imperva, Cloudflare) reportan cientos de
        puertos abiertos que son de la infraestructura del WAF, no del servidor real.
        Httpx ya detecta esto con los campos cdn/cdn_name/cdn_type.

        Args:
            alive_urls: Lista de resultados httpx (dicts con host, a, cdn, etc.)

        Returns:
            Tuple de (nmap_targets, cdn_hosts, ip_to_hostnames)
            - nmap_targets: lista de hostnames únicos por IP, sin CDN/WAF
            - cdn_hosts: lista de hostnames detrás de CDN/WAF (excluidos de nmap)
            - ip_to_hostnames: dict {ip: [hostnames]} para mapeo inverso
        """
        cdn_hosts = []
        non_cdn_urls = []

        for url in alive_urls:
            host = url.get('host', '').split(':')[0]
            if not host:
                continue

            is_cdn = url.get('cdn', False)
            cdn_type = url.get('cdn_type', '')

            if is_cdn:
                cdn_name = url.get('cdn_name', 'unknown')
                cdn_hosts.append({
                    'host': host,
                    'cdn_name': cdn_name,
                    'cdn_type': cdn_type,
                    'status_code': url.get('status_code')
                })
                print(f"  ⚠ {host} → CDN/WAF ({cdn_name}) - excluido de Nmap")
            else:
                non_cdn_urls.append(url)

        # Deduplicar por IP resolvida: solo escanear cada IP una vez
        ip_to_hostnames = {}
        seen_ips = set()
        nmap_targets = []

        for url in non_cdn_urls:
            host = url.get('host', '').split(':')[0]
            # httpx devuelve IPs en el campo 'a' (lista) o 'host' si ya es IP
            ips = url.get('a', [])
            if not ips:
                # Fallback: usar el host directamente
                nmap_targets.append(host)
                continue

            # Tomar la primera IP del registro A
            primary_ip = ips[0] if isinstance(ips, list) else ips

            # Registrar mapeo IP -> hostnames
            if primary_ip not in ip_to_hostnames:
                ip_to_hostnames[primary_ip] = []
            ip_to_hostnames[primary_ip].append(host)

            # Solo agregar si esta IP no fue vista antes
            if primary_ip not in seen_ips:
                seen_ips.add(primary_ip)
                nmap_targets.append(host)
            else:
                existing_host = ip_to_hostnames[primary_ip][0]
                print(f"  ⚠ {host} → misma IP que {existing_host} ({primary_ip}) - deduplicado")

        if cdn_hosts:
            print(f"[Pipeline] {len(cdn_hosts)} hosts CDN/WAF excluidos de Nmap")
        if len(non_cdn_urls) > len(nmap_targets):
            print(f"[Pipeline] {len(non_cdn_urls) - len(nmap_targets)} hosts deduplicados por IP compartida")

        return nmap_targets, cdn_hosts, ip_to_hostnames

    def _prioritize_subdomains(self, subdomains):
        """
        Priorizar subdominios según keywords de interés

        Args:
            subdomains: Lista de subdominios

        Returns:
            Lista priorizada y limitada
        """
        priority_keywords = self.config.get('scope', {}).get('priority_keywords', [])
        exclude_patterns = self.config.get('scope', {}).get('exclude_patterns', [])

        import re

        # Filtrar subdominios excluidos
        filtered = []
        for sub in subdomains:
            # Verificar si coincide con algún patrón de exclusión
            excluded = False
            for pattern in exclude_patterns:
                if re.match(pattern, sub):
                    excluded = True
                    break

            if not excluded:
                filtered.append(sub)

        # Separar prioritarios y normales
        prioritized = []
        normal = []

        for sub in filtered:
            is_priority = False
            for keyword in priority_keywords:
                if keyword in sub.lower():
                    is_priority = True
                    break

            if is_priority:
                prioritized.append(sub)
            else:
                normal.append(sub)

        # Combinar: primero prioritarios, luego normales
        result = prioritized + normal

        # Limitar
        max_subs = self.config['limits']['max_subdomains']
        return result[:max_subs]

    def _collect_results(self):
        """Recopilar resultados de todas las tareas"""
        all_results = self.worker_pool.get_all_results()

        print(f"\n[Orchestrator] Recopilando resultados de {len(all_results)} tareas...")

        # Los resultados ya fueron agregados por cada módulo
        # Aquí solo verificamos completitud

        stats = self.worker_pool.get_stats()
        print(f"  Completadas: {stats['by_status'].get('completed', 0)}")
        print(f"  Fallidas: {stats['by_status'].get('failed', 0)}")
        print(f"  Timeout: {stats['by_status'].get('timeout', 0)}")

    def _save_results(self):
        """Guardar resultados en archivo JSON"""
        output_file = self.output_dir / f"{self.scan_id}.json"

        import json
        with open(output_file, 'w') as f:
            json.dump(self.scan_results, f, indent=2)

        print(f"\n[Orchestrator] Resultados guardados en: {output_file}")

    def _print_summary(self):
        """Imprimir resumen de resultados"""
        print(f"Subdominios encontrados: {len(self.scan_results.get('subdomains', []))}")
        print(f"URLs activas: {len(self.scan_results.get('alive_urls', []))}")
        print(f"IPs escaneadas: {len(self.scan_results.get('ports', {}))}")
        print(f"Vulnerabilidades: {len(self.scan_results.get('vulnerabilities', []))}")

        # Contar vulnerabilidades por severidad
        vulns = self.scan_results.get('vulnerabilities', [])
        if vulns:
            by_severity = {}
            for v in vulns:
                sev = v.get('info', {}).get('severity', 'unknown')
                by_severity[sev] = by_severity.get(sev, 0) + 1

            print("\nVulnerabilidades por severidad:")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = by_severity.get(sev, 0)
                if count > 0:
                    print(f"  {sev.upper()}: {count}")

        print(f"{'='*60}\n")

    def shutdown(self):
        """Cerrar orquestador"""
        print("[Orchestrator] Cerrando...")
        self.worker_pool.shutdown()


# =============================
# Script principal
# =============================

def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(
        description='FAROSINT - Framework de Análisis de Superficie de Ataque OSINT',
        epilog='''
Ejemplos:
  # Escaneo completo de dominio
  %(prog)s example.com -t full

  # Escaneo rápido de dominio
  %(prog)s example.com -t quick

  # Escaneo de red LAN (CIDR)
  %(prog)s 192.168.1.0/24 -t lan

  # Escaneo de IP única
  %(prog)s 192.168.1.100

  # Escaneo de rango de IPs
  %(prog)s 192.168.1.1-192.168.1.50
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'target',
        help='Objetivo: dominio (example.com), IP (192.168.1.1), CIDR (192.168.1.0/24) o rango (192.168.1.1-254)'
    )

    parser.add_argument(
        '-t', '--type',
        choices=['quick', 'full', 'custom', 'lan'],
        default='full',
        help='Tipo de escaneo: quick (rápido), full (completo), lan (red LAN) (default: full - autodetecta si es IP/CIDR)'
    )

    parser.add_argument(
        '-c', '--config',
        help='Archivo de configuración personalizado'
    )

    args = parser.parse_args()

    # Crear orquestador
    orchestrator = FAROSINTOrchestrator(config_file=args.config)

    try:
        # Ejecutar escaneo
        results = orchestrator.scan(args.target, scan_type=args.type)

        # Éxito
        return 0

    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario")
        return 1

    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        orchestrator.shutdown()


if __name__ == "__main__":
    sys.exit(main())
