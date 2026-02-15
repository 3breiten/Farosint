#!/usr/bin/env python3
"""
FAROSINT DNSRecon Module
Reconocimiento DNS: zone transfer, registros, subdominios, SRV, MX
"""

import subprocess
import json
import re
from .base_module import BaseModule


class DNSReconModule(BaseModule):
    """Módulo para dnsrecon - reconocimiento DNS"""

    def __init__(self, timeout=120, cache_manager=None):
        super().__init__("DNSRecon", timeout, cache_manager)

    def run(self, domain, **kwargs):
        """
        Ejecutar dnsrecon contra un dominio

        Returns:
            Dict con: records, zone_transfer, subdomains, mx, ns, txt
        """
        self.log(f"Iniciando reconocimiento DNS de: {domain}")

        dnsrecon_bin = self.get_tool_path('dnsrecon')
        if not dnsrecon_bin:
            self.log("dnsrecon no encontrado", "WARNING")
            return self._empty_result()

        # Verificar caché
        params = {'type': 'std,brt'}
        cached = self.check_cache(domain, params)
        if cached:
            self.log("Usando resultado cacheado")
            return cached

        try:
            cmd = [
                dnsrecon_bin,
                '-d', domain,
                '-t', 'std,brt',   # standard + brute force básico
                '-j', '/dev/stdout',
                '--lifetime', '3',
                '--threads', '10',
            ]

            self.log(f"Ejecutando: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            parsed = self._parse_output(result.stdout, result.stderr, domain)
            self.update_cache(domain, parsed, params)
            return parsed

        except subprocess.TimeoutExpired:
            self.log(f"Timeout después de {self.timeout}s", "WARNING")
            return self._empty_result()
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            return self._empty_result()

    def _parse_output(self, stdout, stderr, domain):
        """Parsear output JSON de dnsrecon"""
        result = self._empty_result()

        try:
            # dnsrecon a veces mezcla texto con JSON
            json_start = stdout.find('[')
            json_end = stdout.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                records_raw = json.loads(stdout[json_start:json_end])
            else:
                json_match = re.search(r'\[.*\]', stdout, re.DOTALL)
                if not json_match:
                    return self._parse_text(stdout, domain)
                records_raw = json.loads(json_match.group())

            for record in records_raw:
                rec_type = record.get('type', '').upper()
                name = record.get('name', '')
                address = record.get('address', record.get('target', record.get('strings', '')))
                exchange = record.get('exchange', '')

                entry = {'type': rec_type, 'name': name, 'value': address or exchange}

                if rec_type == 'A':
                    result['a_records'].append(entry)
                    if name != domain and name.endswith(f'.{domain}'):
                        subdomain = name.rstrip('.')
                        if subdomain not in result['subdomains']:
                            result['subdomains'].append(subdomain)
                elif rec_type == 'MX':
                    result['mx_records'].append({'name': name, 'exchange': exchange, 'preference': record.get('preference', 0)})
                elif rec_type == 'NS':
                    result['ns_records'].append({'name': name, 'nameserver': address})
                elif rec_type == 'TXT':
                    result['txt_records'].append({'name': name, 'text': str(address)})
                elif rec_type == 'AXFR':
                    result['zone_transfer'] = True
                    result['all_records'].append(entry)
                elif rec_type in ('CNAME', 'SOA', 'SRV', 'PTR'):
                    result['all_records'].append(entry)

            self.log(f"DNS recon: {len(result['a_records'])} A, {len(result['mx_records'])} MX, {len(result['subdomains'])} subdominios, zone_transfer={result['zone_transfer']}")
            return result

        except Exception as e:
            self.log(f"JSON parse falló: {e}, intentando texto", "WARNING")
            return self._parse_text(stdout, domain)

    def _parse_text(self, stdout, domain):
        """Parseo de texto como fallback"""
        result = self._empty_result()
        for line in stdout.split('\n'):
            a_match = re.search(r'A\s+([\w\.\-]+)\s+([\d\.]+)', line)
            if a_match:
                result['a_records'].append({'type': 'A', 'name': a_match.group(1), 'value': a_match.group(2)})
            mx_match = re.search(r'MX\s+[\w\.\-]+\s+([\w\.\-]+)', line)
            if mx_match:
                result['mx_records'].append({'name': mx_match.group(1), 'exchange': mx_match.group(1), 'preference': 10})
            if 'Zone Transfer' in line and 'was successful' in line.lower():
                result['zone_transfer'] = True
        return result

    def _empty_result(self):
        return {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'all_records': [],
            'subdomains': [],
            'zone_transfer': False
        }
