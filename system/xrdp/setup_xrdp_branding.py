#!/usr/bin/env python3
"""Configura xrdp con branding FAROSINT: logo propio, solo sesión Xorg, título FAROSINT"""
import shutil
import re

# 1. Copiar logo al directorio de xrdp
shutil.copy('/home/farosint/Farosint.bmp', '/usr/share/xrdp/farosint_logo.bmp')
print("✓ Logo copiado a /usr/share/xrdp/farosint_logo.bmp")

# 2. Leer xrdp.ini
with open('/etc/xrdp/xrdp.ini', 'r') as f:
    content = f.read()

# 3. Eliminar secciones Xvnc, vnc-any y neutrinordp-any
# Cada sección empieza con [Nombre] y termina donde empieza la siguiente
sections_to_remove = ['Xvnc', 'vnc-any', 'neutrinordp-any']
for section in sections_to_remove:
    # Elimina desde [section] hasta la siguiente sección [ o fin de archivo
    content = re.sub(
        r'\[' + re.escape(section) + r'\].*?(?=\n\[|\Z)',
        '',
        content,
        flags=re.DOTALL
    )
    print(f"✓ Sección [{section}] eliminada")

# 4. Configurar logo
content = re.sub(r'^ls_logo_filename=.*$', 'ls_logo_filename=/usr/share/xrdp/farosint_logo.bmp', content, flags=re.MULTILINE)
content = re.sub(r'^#ls_logo_width=.*$', 'ls_logo_width=141', content, flags=re.MULTILINE)
content = re.sub(r'^#ls_logo_height=.*$', 'ls_logo_height=159', content, flags=re.MULTILINE)
content = re.sub(r'^ls_logo_x_pos=.*$', 'ls_logo_x_pos=104', content, flags=re.MULTILINE)  # centrado: (350-141)/2
content = re.sub(r'^ls_logo_y_pos=.*$', 'ls_logo_y_pos=15', content, flags=re.MULTILINE)
print("✓ Logo configurado (141x159, centrado)")

# 5. Ajustar altura del panel para que no se superpongan logo e inputs
# logo termina en y=15+159=174, necesitamos inputs más abajo
content = re.sub(r'^ls_height=.*$', 'ls_height=460', content, flags=re.MULTILINE)
content = re.sub(r'^ls_input_y_pos=.*$', 'ls_input_y_pos=230', content, flags=re.MULTILINE)
content = re.sub(r'^ls_btn_ok_y_pos=.*$', 'ls_btn_ok_y_pos=400', content, flags=re.MULTILINE)
content = re.sub(r'^ls_btn_cancel_y_pos=.*$', 'ls_btn_cancel_y_pos=400', content, flags=re.MULTILINE)
print("✓ Layout ajustado para logo 159px de alto")

# 6. Título de ventana
content = re.sub(r'^#ls_title=.*$', 'ls_title=FAROSINT - Remote Access', content, flags=re.MULTILINE)
print("✓ Título configurado: FAROSINT - Remote Access")

# 7. Guardar
with open('/etc/xrdp/xrdp.ini', 'w') as f:
    f.write(content)
print("✓ xrdp.ini guardado")

import subprocess
subprocess.run(['systemctl', 'restart', 'xrdp'], check=True)
print("✓ xrdp reiniciado")
print("\n¡Listo! Conectate por RDP para ver los cambios.")
