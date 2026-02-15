#!/usr/bin/env python3
"""
FAROSINT Network Utilities
Funciones para manejo de IPs, CIDR y network scanning
"""

import ipaddress
import re
import subprocess
from typing import List, Tuple, Union


def detect_target_type(target: str) -> str:
    """
    Detecta el tipo de target

    Args:
        target: String que puede ser dominio, IP, CIDR, o rango

    Returns:
        'domain', 'ip', 'cidr', o 'range'
    """
    # Remover espacios
    target = target.strip()

    # Detectar CIDR (192.168.1.0/24)
    if '/' in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return 'cidr'
        except ValueError:
            pass

    # Detectar rango (192.168.1.1-192.168.1.254)
    if '-' in target and not target.startswith('-'):
        parts = target.split('-')
        if len(parts) == 2:
            try:
                ipaddress.ip_address(parts[0].strip())
                # Verificar si es IP-IP o IP-número
                if '.' in parts[1]:
                    ipaddress.ip_address(parts[1].strip())
                else:
                    int(parts[1].strip())
                return 'range'
            except ValueError:
                pass

    # Detectar IP simple
    try:
        ipaddress.ip_address(target)
        return 'ip'
    except ValueError:
        pass

    # Por defecto es dominio
    return 'domain'


def expand_cidr(cidr: str) -> List[str]:
    """
    Expande notación CIDR a lista de IPs

    Args:
        cidr: Notación CIDR (ej: 192.168.1.0/24)

    Returns:
        Lista de IPs como strings
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Excluir network address y broadcast
        hosts = list(network.hosts())
        return [str(ip) for ip in hosts]
    except ValueError as e:
        raise ValueError(f"CIDR inválido '{cidr}': {e}")


def expand_range(ip_range: str) -> List[str]:
    """
    Expande rango de IPs

    Args:
        ip_range: Rango en formato:
                  - 192.168.1.1-192.168.1.254 (IP-IP)
                  - 192.168.1.1-254 (IP-número)

    Returns:
        Lista de IPs como strings
    """
    parts = ip_range.split('-')
    if len(parts) != 2:
        raise ValueError(f"Rango inválido: {ip_range}")

    start_ip = parts[0].strip()
    end_part = parts[1].strip()

    try:
        start = ipaddress.ip_address(start_ip)

        # Verificar si end_part es IP completa o solo último octeto
        if '.' in end_part:
            end = ipaddress.ip_address(end_part)
        else:
            # Reconstruir IP final
            octets = str(start_ip).split('.')
            octets[-1] = end_part
            end = ipaddress.ip_address('.'.join(octets))

        # Generar rango
        if start > end:
            raise ValueError("IP inicial debe ser menor que IP final")

        ips = []
        current = start
        while current <= end:
            ips.append(str(current))
            current = ipaddress.ip_address(int(current) + 1)

        return ips

    except ValueError as e:
        raise ValueError(f"Rango inválido '{ip_range}': {e}")


def expand_target(target: str, max_hosts: int = 254) -> Tuple[str, List[str]]:
    """
    Expande target según su tipo

    Args:
        target: Dominio, IP, CIDR o rango
        max_hosts: Máximo de hosts a retornar (para evitar escanear /8)

    Returns:
        Tupla (tipo, lista_de_hosts)
    """
    target_type = detect_target_type(target)

    if target_type == 'domain':
        return ('domain', [target])

    elif target_type == 'ip':
        return ('ip', [target])

    elif target_type == 'cidr':
        hosts = expand_cidr(target)
        if len(hosts) > max_hosts:
            raise ValueError(
                f"CIDR {target} genera {len(hosts)} hosts. "
                f"Máximo permitido: {max_hosts}. "
                f"Use un rango más pequeño."
            )
        return ('cidr', hosts)

    elif target_type == 'range':
        hosts = expand_range(target)
        if len(hosts) > max_hosts:
            raise ValueError(
                f"Rango {target} genera {len(hosts)} hosts. "
                f"Máximo permitido: {max_hosts}. "
                f"Use un rango más pequeño."
            )
        return ('range', hosts)

    else:
        raise ValueError(f"Tipo de target desconocido: {target}")


def nmap_ping_sweep(targets: Union[str, List[str]], timeout: int = 300) -> List[str]:
    """
    Realiza ping sweep con Nmap para encontrar hosts vivos

    Args:
        targets: IP, CIDR o lista de IPs
        timeout: Timeout en segundos

    Returns:
        Lista de IPs que respondieron
    """
    if isinstance(targets, list):
        # Si es lista, crear string separado por espacios
        target_str = ' '.join(targets)
    else:
        target_str = targets

    # Comando Nmap: ping scan sin port scan
    cmd = ['nmap', '-sn', '-n', '--max-retries', '2', '-T4', target_str]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parsear salida para extraer IPs vivas
        alive_hosts = []
        for line in result.stdout.split('\n'):
            # Buscar líneas como "Nmap scan report for 192.168.1.1"
            if 'Nmap scan report for' in line:
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    alive_hosts.append(ip_match.group())

        return alive_hosts

    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Ping sweep excedió timeout de {timeout}s")
    except Exception as e:
        raise RuntimeError(f"Error en ping sweep: {e}")


def is_private_network(ip: str) -> bool:
    """
    Verifica si una IP pertenece a red privada

    Args:
        ip: Dirección IP

    Returns:
        True si es privada, False si es pública
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_network_info(cidr: str) -> dict:
    """
    Obtiene información sobre una red CIDR

    Args:
        cidr: Notación CIDR

    Returns:
        Dict con info de la red
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'num_addresses': network.num_addresses,
            'num_hosts': len(list(network.hosts())),
            'is_private': network.is_private
        }
    except ValueError as e:
        raise ValueError(f"CIDR inválido '{cidr}': {e}")
