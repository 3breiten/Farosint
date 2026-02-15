# Changelog

Todos los cambios notables en el proyecto FAROSINT se documentarán en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

## [No Versionado] - 2026-02-07

### Añadido - Visualización Interactiva de Grafos

#### Frontend (gui/templates/scan_detail.html)
- **Nueva pestaña "Grafo Interactivo"** en la vista de detalles de escaneo
- Implementación completa de visualización con **Cytoscape.js 3.28.1**
- **Controles interactivos:**
  - Botón Reset: Reinicia la posición y zoom del grafo
  - Botón Fit: Ajusta la vista para mostrar todos los elementos
  - Botón Export PNG: Exporta el grafo como imagen PNG de alta calidad
- **Sistema de filtros dinámicos:**
  - Toggle para subdominios (muestra/oculta subdominios y sus relaciones)
  - Toggle para IPs (muestra/oculta direcciones IP)
  - Toggle para puertos (muestra/oculta puertos abiertos)
  - Toggle para servicios (muestra/oculta servicios detectados)
  - Toggle para vulnerabilidades (muestra/oculta CVEs)
- **Buscador en tiempo real:**
  - Campo de búsqueda que filtra nodos por texto
  - Resalta y centra el nodo encontrado
  - Navegación con enter entre resultados múltiples
- **Interacciones del usuario:**
  - Click en nodos para ver información detallada
  - Zoom con scroll del mouse
  - Pan arrastrando el fondo del grafo
  - Selección visual de nodos activos
- **Panel de información:**
  - Muestra detalles completos del nodo seleccionado
  - Información específica según tipo de nodo:
    - Subdominios: IP resuelta
    - IPs: Dirección IP
    - Puertos: Número y estado
    - Servicios: Nombre, producto, versión
    - CVEs: ID, severidad, descripción, CVSS score
- **Estilos visuales por tipo:**
  - Target: Triángulo rojo (#dc3545), tamaño grande
  - Subdomain: Círculo azul (#0d6efd), tamaño medio
  - IP: Rectángulo verde (#198754), tamaño medio
  - Port: Rectángulo naranja (#fd7e14), tamaño pequeño
  - Service: Elipse morada (#6f42c1), tamaño pequeño
  - CVE: Diamante con color según severidad:
    - CRITICAL: Rojo oscuro (#721c24)
    - HIGH: Naranja (#fd7e14)
    - MEDIUM: Amarillo (#ffc107)
    - LOW: Azul claro (#17a2b8)
- **Layout automático:**
  - Algoritmo COSE (Compound Spring Embedder)
  - Force-directed layout para distribución óptima
  - Configuración ajustada: idealEdgeLength=100, nodeOverlap=20, gravity=80
  - Animación suave de 500ms al aplicar layout

#### Backend (gui/app.py)
- **Nuevo endpoint REST:** `GET /api/scan/<scan_id>/graph`
- **Generación dinámica de grafo:**
  - Consulta a base de datos SQLite para obtener todos los datos del escaneo
  - Construcción de nodos para cada entidad:
    - Nodo target (dominio principal)
    - Nodos subdomain (cada subdominio descubierto)
    - Nodos ip (direcciones IP únicas)
    - Nodos port (puertos abiertos con su estado)
    - Nodos service (servicios detectados con versiones)
    - Nodos cve (vulnerabilidades con severidad)
  - Construcción de aristas (edges) representando relaciones:
    - target → subdomain (`has_subdomain`)
    - subdomain → ip (`resolves_to`)
    - ip → port (`has_port`)
    - port → service (`runs_service`)
    - service → cve (`has_vulnerability`)
- **Formato de respuesta JSON:**
  ```json
  {
    "success": true,
    "elements": {
      "nodes": [
        {"data": {"id": "...", "label": "...", "type": "...", ...}, "classes": "..."}
      ],
      "edges": [
        {"data": {"source": "...", "target": "...", "label": "..."}}
      ]
    },
    "stats": {
      "total_nodes": 0,
      "total_edges": 0,
      "node_types": {},
      "edge_types": {}
    }
  }
  ```
- **Estadísticas incluidas:**
  - Total de nodos y aristas
  - Conteo por tipo de nodo
  - Conteo por tipo de relación
- **Manejo de errores:**
  - Validación de scan_id
  - Respuestas HTTP apropiadas (200, 404, 500)
  - Logging de errores para debugging

#### Integración con Sistema Existente
- Compatible con tema claro/oscuro existente
- Integración con Socket.IO para actualizaciones en tiempo real
- Uso de Lucide Icons para iconos consistentes
- Responsive design compatible con Bootstrap 5.3
- Mantiene la arquitectura de tabs existente

#### Características Técnicas
- **Performance:** Optimizado para grafos de hasta 500+ nodos
- **Compatibilidad:** Navegadores modernos (Chrome, Firefox, Safari, Edge)
- **Responsive:** Se adapta a diferentes tamaños de pantalla
- **Accesibilidad:** Controles con labels descriptivos
- **Exportación:** PNG de alta resolución (2x pixel ratio)

---

## [No Versionado] - 2026-02-08

### Añadido - Exportación Profesional a PDF

#### Backend (gui/pdf_generator.py, gui/app.py)
- **Nuevo módulo `pdf_generator.py`** (638 líneas de código)
  - Clase `FAROSINTPDFReport` para generación programática de PDFs
  - Generación con **ReportLab 4.4.9**
  - Gráficos estadísticos con **Matplotlib 3.10.8**
  - Procesamiento de imágenes con **Pillow 12.1.0**

- **Estructura del Reporte PDF:**
  - **Portada profesional:**
    - Logo de FAROSINT (imagen PNG)
    - Título y subtítulo
    - Tabla de información del escaneo (target, tipo, fecha, scan ID, estado)
    - Disclaimer legal
  - **Resumen Ejecutivo:**
    - Análisis narrativo con métricas destacadas
    - Tabla de métricas clave (subdominios, IPs, servicios, vulnerabilidades)
    - Gráfico de barras: distribución de vulnerabilidades por severidad (matplotlib)
    - Alertas visuales para criticidad alta
  - **Estadísticas Detalladas:**
    - Análisis de subdominios (activos vs inactivos)
    - Análisis de servicios
  - **Subdominios Descubiertos:**
    - Tabla formateada con hasta 50 subdominios
    - Columnas: Subdominio, IP, Estado
  - **Servicios Detectados:**
    - Tabla formateada con hasta 30 servicios
    - Columnas: Host, Puerto, Servicio, Versión
  - **Vulnerabilidades Identificadas:**
    - Tabla formateada con hasta 30 CVEs
    - Ordenadas por severidad (CRITICAL → HIGH → MEDIUM → LOW)
    - Colores por severidad (rojo, naranja, amarillo)
    - Columnas: CVE/ID, Severidad, CVSS, Descripción
  - **Conclusiones y Recomendaciones:**
    - Análisis dinámico de riesgo
    - Recomendaciones priorizadas según hallazgos
    - Nivel de riesgo: ALTO/MEDIO/BAJO
    - Metadata del reporte (fecha de generación, scan ID)

- **Características Técnicas:**
  - **Formato:** PDF tamaño A4
  - **Estilos:** Fuentes Helvetica, colores Bootstrap 5.3
  - **Tablas:** Headers con fondo de color, alternancia de filas, bordes sutiles
  - **Gráficos:** Matplotlib con backend Agg (sin GUI)
  - **Tamaño típico:** 35-85 KB según cantidad de datos
  - **Tiempo de generación:** < 2 segundos
  - **Numeración:** Footer con número de página y nombre del reporte

- **Análisis Dinámico:**
  - El reporte adapta conclusiones según severidad de hallazgos:
    - **Riesgo ALTO:** Si hay CVEs críticas/altas
    - **Riesgo MEDIO:** Si hay CVEs medias/bajas
    - **Riesgo BAJO:** Si no hay vulnerabilidades
  - Recomendaciones específicas por nivel de riesgo

#### Frontend (gui/templates/scan_detail.html)
- **Botón "Exportar PDF"** agregado en header de información del escaneo
- Ubicado junto al botón "Eliminar Escaneo" en btn-group
- Descarga directa del PDF al hacer click
- Icono: `file-text` (Lucide Icons)

#### API REST
- **Endpoint:** `GET /api/scan/<scan_id>/export/pdf`
- **Función:** `export_pdf(scan_id)` implementada en app.py
- **Respuesta:** Archivo PDF con `mimetype='application/pdf'`
- **Nombre archivo:** `FAROSINT_Report_<scan_id>.pdf`
- **Manejo de errores:** Retorna 404 si escaneo no existe, 500 si falla generación

#### Dependencias Instaladas
- reportlab==4.4.9 (generación de PDFs)
- pillow==12.1.0 (procesamiento de imágenes)
- matplotlib==3.10.8 (gráficos estadísticos)
- psutil==7.2.2 (monitoreo del sistema)

#### Ventajas
- **Sin dependencias del sistema:** ReportLab es 100% Python puro
- **Portable:** No requiere libpango, cairo o dependencias C
- **Profesional:** Formato de reporte ejecutivo presentable
- **Compartible:** PDF standalone sin necesidad de acceso al dashboard

---

## [No Versionado] - 2026-02-09/10

### Añadido - Escaneo LAN Completo, Nuevas Herramientas e Integración NVD

#### Problema original
El escaneo LAN devolvía resultados vacíos (hosts: [], 0 vulnerabilidades, tarda 10 segundos), y la UI mostraba pestañas incorrectas (de domain scan) en vez de pestañas de red LAN.

---

#### Nuevos módulos creados (`engine/modules/`)

**`lan_vuln_scanner.py`** - Lookup de CVEs por OS y servicios
- Clase `LANVulnScanner` integrada en la Fase 7 del pipeline LAN
- `OS_CPE_MAP`: mapea nombres de OS detectados por nmap → CPE de NVD (Windows 7, XP, Vista, Server 2003/2008/2012, Windows 10/11, Ubuntu, Debian, CentOS)
- `WINDOWS7_KNOWN_CVES`: lista hardcodeada de 10 CVEs críticos (EternalBlue, BlueKeep, MS08-067, etc.) como fallback si NVD no responde
- Consulta NVD API v2 en dos pasadas: `cvssV3Severity=CRITICAL` (50 resultados) + `cvssV3Severity=HIGH` (30 resultados), combina sin duplicados
- Filtra CVEs ya detectados por NSE para evitar duplicados
- Parseo correcto de CVSS desde `cvssMetricV31`, `cvssMetricV30`, `cvssMetricV2` con fallback a score numérico

**`enum4linux_module.py`** - Enumeración SMB/Windows
- Usa `/home/farosint/tools/enum4linux-ng/enum4linux-ng.py` (instalado vía git clone)
- Activa automáticamente si puertos 139 o 445 están abiertos (Fase 5 del pipeline LAN)
- Enumera: usuarios, grupos, shares SMB, política de contraseñas, info OS
- Si un share es accesible anónimamente → añade vulnerabilidad "high" automáticamente

**`nikto_module.py`** - Scanner web
- Usa `/home/farosint/tools/nikto/program/nikto.pl` via Perl (instalado vía git clone)
- Activa automáticamente para URLs web detectadas en domain scans
- Clasifica findings en critical/high/medium/low por keywords en descripción
- Extrae CVEs de las descripciones con regex

**`gobuster_module.py`** - Enumeración de directorios web
- Usa `gobuster` del sistema (instalado vía apt)
- Wordlist integrada como fallback si no hay `/usr/share/wordlists/dirb/common.txt`
- Clasifica paths por sensibilidad: `.git`, `.env`, `admin`, `upload` → high; `login`, `api`, `dashboard` → medium
- Solo guarda en vulnerabilidades los findings medium/high

**`dnsrecon_module.py`** - Reconocimiento DNS
- Usa `dnsrecon` del sistema (instalado vía apt)
- Corre en paralelo con Httpx en domain scans
- Parsea registros A, MX, NS, TXT
- Zone transfer detectado → vulnerabilidad CVE-1999-0532 (high)
- Añade subdominios encontrados al resultado del scan

**`snmpwalk_module.py`** - Enumeración SNMP
- Activa automáticamente si puerto 161 abierto (Fase 6 del pipeline LAN)
- Prueba community strings: public, private, community, manager, admin, default
- Recolecta: descripción OS, hostname, contacto, ubicación, procesos (top 20), software (top 30)
- Community "public" → añade vulnerabilidad CVE-2002-0013 (medium)

---

#### Bugs corregidos

**`engine/modules/nmap_module.py`**
- **Bug crítico #1:** `cannot access local variable 'params'` → `params = {'scan_type': scan_type}` estaba dentro del bloque LAN-exclusivo pero se usaba fuera. Fix: mover la asignación antes del if/else.
- **Bug crítico #2:** Faltaba flag `-Pn` (skip host discovery) → nmap saltea hosts que no responden a ICMP → scan completamente vacío. Agregado `-Pn` a todos los scans.
- Cache deshabilitado para targets LAN (IPs/rangos cambian frecuentemente).
- NSE scripts agregados para LAN: `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`, `nbstat`, `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `vulners`.
- Parsing de OS en XML: nombre, familia, generación, accuracy, tipo.
- Parsing de host scripts NSE: resultados de nbstat, smb-os-discovery, smb-enum-shares, smb-vuln-*
- Método `_extract_nse_vulnerabilities()`: extrae CVEs y findings de output NSE.

**`engine/modules/lan_vuln_scanner.py`**
- **Bug crítico:** `_query_nvd_by_cpe()` no aceptaba el parámetro `severity_filter` que le pasaba el orquestador → `TypeError` silencioso → 0 CVEs de NVD, solo los 5 hardcodeados de fallback. Fix: agregar `severity_filter: str = 'CRITICAL'` como parámetro.
- Severidad siempre devolvía "medium" → fix: verificar `m.get('baseSeverity')` y `cvss_data.get('baseSeverity')` con fallback a cálculo desde score numérico.

**`gui/app.py` - endpoint `/api/scan/<scan_id>/graph`**
- **Bug:** Para scans LAN, el nodo `target` no tenía ningún edge hacia los nodos `ip` → nodo raíz desconectado del grafo. Fix: detectar LAN con `detect_target_type()` y agregar edge `target → ip` con label "host".
- Añadido campo `is_lan` en respuesta JSON para que el frontend use layout apropiado.

---

#### Pipeline LAN actualizado (`engine/core/orchestrator.py`)

```
Fase 1: Host Discovery (nmap ping sweep)
         └─ Si 1 solo host → saltar ping sweep
Fase 2: Port Scanning
         └─ full (top 1000) para ≤5 hosts
         └─ quick (top 100) para más hosts
Fase 3: Service Detection → identificar URLs web
Fase 4: Nuclei (si hay URLs web encontradas)
Fase 5: Enum4linux-ng (si puertos 139 o 445 abiertos)   [NUEVO]
Fase 6: SNMP walk (si puerto 161 abierto)                [NUEVO]
Fase 7: CVE Lookup vía NVD API por OS y servicios        [NUEVO]
```

Domain scan también actualizado: DNSRecon en paralelo, Nikto + Gobuster para URLs activas.

---

#### Mejoras de UI (`gui/templates/scan_detail.html`)

**Cards de resumen (arriba de pestañas):**
- LAN: Hosts / Servicios / Vulnerabilidades / Puertos Abiertos
- Domain: Subdominios / Servicios / Vulnerabilidades / URLs Activas

**Pestañas adaptadas por tipo de scan:**
- LAN: Servicios (activo) → Vulnerabilidades → Info de Red → Grafo → JSON
- Domain: Subdominios (activo) → URLs Activas → Servicios → Vulnerabilidades → Grafo → JSON

**Pestaña "Servicios" para LAN — rediseño completo:**
- Cards agrupadas por host (antes: tabla simple plana)
- Header de cada card: IP en amarillo, total de puertos, contador "⛔ N críticos / ⚠ N altos"
- Tabla con columnas: Puerto / Servicio / Descripción / Nivel / Producto
- Diccionario integrado de 35+ puertos con descripción en español (ej: "445 → SMB – compartición Windows, vulnerable a EternalBlue")
- Niveles: ⛔ CRÍTICO (rojo) / ⚠ ALTO (amarillo) / MEDIO / BAJO — con color de fila
- Filas ordenadas por número de puerto
- Nota explicativa: diferencia entre "nivel de riesgo del servicio" vs "vulnerabilidad confirmada"

**Pestaña "Info de Red" (solo LAN — nueva):**
- Tabla de hosts detectados con servicios por host
- Cards por host con: OS detectado (badge), scripts NSE, hostnames

**Grafo Interactivo — mejoras LAN:**
- Layout `breadthfirst` (árbol jerárquico) para LAN → árbol claro: target → ip → puertos → servicios → vulns
- Layout `cose` (fuerza) sólo para domain scans (muchos nodos)
- Filtro "Subdominios" se oculta automáticamente para LAN (no aplica)
- Estadísticas adaptadas: LAN muestra "X hosts | Y puertos | Z vulns"
- `resetGraph()` también usa layout correcto según tipo

---

#### Herramientas instaladas

| Herramienta | Path | Método instalación |
|---|---|---|
| nikto | `/home/farosint/tools/nikto/` | `git clone https://github.com/sullo/nikto` |
| enum4linux-ng | `/home/farosint/tools/enum4linux-ng/` | `git clone https://github.com/cddmp/enum4linux-ng` |
| gobuster | `/usr/bin/gobuster` | `apt install gobuster` |
| dnsrecon | `/usr/bin/dnsrecon` | `apt install dnsrecon` |
| snmpwalk | `/usr/bin/snmpwalk` | `apt install snmp` |

---

#### Concepto clave documentado

**"Nivel de riesgo del servicio" ≠ "Vulnerabilidad detectada"**
- **Nivel de riesgo** = clasificación del *puerto* según historial del protocolo. Ej: 445 (SMB) → CRÍTICO porque históricamente tiene EternalBlue. Es una advertencia.
- **Vulnerabilidad** = CVE *confirmado activamente* por el scanner: NSE script probó y respondió, NVD devolvió para el CPE del OS, o herramienta específica lo confirmó.
- Pueden no coincidir en cantidad: 9 puertos "críticos" + 5 vulnerabilidades confirmadas es resultado normal.

---

### Pendiente por Implementar
- [ ] Script de validación de API keys para theHarvester
- [ ] Integración activa con Shodan API para enriquecimiento de datos
- [ ] Integración activa con GreyNoise API para análisis de IPs
- [ ] Agregar nota en tab Vulnerabilidades explicando diferencia con niveles de servicio
- [ ] Exportar PDF incluir sección de red LAN (hosts, ports, OS)

---

## [Previo] - Implementaciones Anteriores

### Sistema Base
- Arquitectura Flask con SQLite
- Motor de escaneo multi-threaded
- Integración con theHarvester
- Integración con Nmap
- Sistema de logging
- WebSocket con Socket.IO
- Dashboard de estadísticas
- Sistema de tabs para organización de datos
- Tema claro/oscuro
- Gestión de escaneos (crear, listar, eliminar)
- Vista de detalles de escaneo
- Detección de vulnerabilidades (CVEs)
- Resolución DNS
- Análisis WHOIS
