#!/usr/bin/env python3
"""
FAROSINT enum4linux-ng Module
Enumeración de Windows/Samba via SMB: usuarios, shares, políticas
"""

import subprocess
import json
import re
from pathlib import Path
from .base_module import BaseModule


ENUM4LINUX_PATH = Path.home() / "tools" / "enum4linux-ng" / "enum4linux-ng.py"
VENV_PYTHON = Path.home() / "FAROSINT" / "farosint-env" / "bin" / "python3"


class Enum4linuxModule(BaseModule):
    """Módulo para enum4linux-ng - enumeración SMB/Windows"""

    def __init__(self, timeout=120, cache_manager=None):
        super().__init__("Enum4linux-ng", timeout, cache_manager)

    def run(self, target, **kwargs):
        """
        Ejecutar enum4linux-ng contra un target

        Returns:
            Dict con: users, groups, shares, password_policy, os_info
        """
        self.log(f"Iniciando enumeración SMB de: {target}")

        if not ENUM4LINUX_PATH.exists():
            self.log("enum4linux-ng no encontrado", "WARNING")
            return self._empty_result()

        try:
            cmd = [
                str(VENV_PYTHON), str(ENUM4LINUX_PATH),
                '-A',        # All: users, groups, shares, policies, OS
                '-oJ', '-',  # Output JSON to stdout
                target
            ]

            self.log(f"Ejecutando: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            return self._parse_output(result.stdout, result.stderr, target)

        except subprocess.TimeoutExpired:
            self.log(f"Timeout después de {self.timeout}s", "WARNING")
            return self._empty_result()
        except Exception as e:
            self.log(f"Error: {e}", "ERROR")
            return self._empty_result()

    def _parse_output(self, stdout, stderr, target):
        """Parsear output JSON de enum4linux-ng"""
        result = self._empty_result()

        # Intentar parsear JSON
        try:
            # enum4linux-ng puede mezclar texto con JSON, buscar el bloque JSON
            json_match = re.search(r'\{.*\}', stdout, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                smb_data = data.get('smb', {})

                # Usuarios
                users_data = data.get('users', {})
                if isinstance(users_data, dict):
                    for uid, user_info in users_data.items():
                        if isinstance(user_info, dict):
                            result['users'].append({
                                'username': user_info.get('username', uid),
                                'rid': user_info.get('rid', uid),
                                'comment': user_info.get('comment', '')
                            })

                # Grupos
                groups_data = data.get('groups', {})
                if isinstance(groups_data, dict):
                    for gid, group_info in groups_data.items():
                        if isinstance(group_info, dict):
                            result['groups'].append({
                                'name': group_info.get('groupname', gid),
                                'rid': group_info.get('rid', gid)
                            })

                # Shares
                shares_data = data.get('shares', {})
                if isinstance(shares_data, dict):
                    for share_name, share_info in shares_data.items():
                        if isinstance(share_info, dict):
                            result['shares'].append({
                                'name': share_name,
                                'type': share_info.get('type', 'Disk'),
                                'comment': share_info.get('comment', ''),
                                'access': share_info.get('access', 'unknown')
                            })

                # Password policy
                pp = data.get('password_policy', {})
                if pp:
                    result['password_policy'] = {
                        'min_length': pp.get('min_passwd_length', 'N/A'),
                        'max_age': pp.get('max_passwd_age', 'N/A'),
                        'lockout_threshold': pp.get('account_lockout_threshold', 'N/A'),
                    }

                # OS info
                os_data = data.get('os_info', smb_data)
                if os_data:
                    result['os_info'] = {
                        'os': os_data.get('os', ''),
                        'domain': os_data.get('domain', ''),
                        'dns_domain': os_data.get('dns_domain', ''),
                        'computer_name': os_data.get('computer_name', ''),
                        'netbios_name': os_data.get('NetBIOS_computer_name', '')
                    }

                self.log(f"Enumeración completada: {len(result['users'])} usuarios, {len(result['shares'])} shares")
                return result

        except (json.JSONDecodeError, Exception) as e:
            self.log(f"JSON parse falló, intentando parseo de texto: {e}", "WARNING")

        # Fallback: parseo de texto del output
        return self._parse_text_output(stdout, stderr)

    def _parse_text_output(self, stdout, stderr):
        """Parseo de texto como fallback"""
        result = self._empty_result()
        combined = stdout + stderr

        # Usuarios (formato: username:rid)
        for line in combined.split('\n'):
            user_match = re.search(r'user:\[(\w+)\]', line, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
                if username not in [u['username'] for u in result['users']]:
                    result['users'].append({'username': username, 'rid': '', 'comment': ''})

            # Shares
            share_match = re.search(r'Sharename\s+(.+?)\s+Disk', line, re.IGNORECASE)
            if share_match:
                result['shares'].append({'name': share_match.group(1).strip(), 'type': 'Disk', 'comment': '', 'access': 'unknown'})

        self.log(f"Parseo texto: {len(result['users'])} usuarios, {len(result['shares'])} shares")
        return result

    def _empty_result(self):
        return {
            'users': [],
            'groups': [],
            'shares': [],
            'password_policy': {},
            'os_info': {}
        }
