#!/usr/bin/env python3
"""
FAROSINT Dashboard - VERSIÓN MEJORADA
Incluye: MITRE/OWASP/CVE, Gráficos, Exportación
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from flask_socketio import SocketIO, emit
from pathlib import Path
import sys
import threading
import json
from datetime import datetime
import io

# Agregar path del engine
engine_path = Path(__file__).resolve().parent.parent / "engine"
sys.path.insert(0, str(engine_path))

from database import DatabaseManager
from core.orchestrator import FAROSINTOrchestrator
from utils.health_check import SystemHealthCheck
from pdf_generator import generate_pdf_report
from modules.network_utils import detect_target_type

# Inicializar Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'farosint-secret-key-change-in-production'
app.config['DEBUG'] = True

# Inicializar SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Inicializar base de datos
db = DatabaseManager()

# Variable global
current_orchestrator = None

# =============================
# RUTAS PRINCIPALES
# =============================

@app.route('/')
def index():
    """Dashboard principal con estadísticas"""
    stats = db.get_stats()
    recent_scans = db.get_all_scans(limit=10)
    
    # Calcular estadísticas adicionales
    severity_stats = get_severity_statistics()
    
    return render_template('index.html',
                         stats=stats,
                         recent_scans=recent_scans,
                         severity_stats=severity_stats)

@app.route('/scan/new')
def scan_new():
    """Formulario para nuevo escaneo"""
    return render_template('scan_new.html')

@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    """Detalle de un escaneo con MITRE/OWASP"""
    scan = db.get_scan(scan_id)
    
    if not scan:
        return "Escaneo no encontrado", 404
    
    # Obtener resultados
    subdomains = db.get_subdomains(scan_id)
    services = db.get_services(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    raw_results = db.get_raw_results(scan_id)
    
    # Enriquecer vulnerabilidades con referencias
    vulnerabilities_enriched = []
    for vuln in vulnerabilities:
        enriched = dict(vuln)
        
        # Parsear referencias si están en JSON
        if vuln.get('references'):
            try:
                enriched['references'] = json.loads(vuln['references'])
            except:
                enriched['references'] = {}
        
        vulnerabilities_enriched.append(enriched)
    
    # Estadísticas de severidad para este scan
    severity_counts = {}
    for vuln in vulnerabilities:
        sev = vuln.get('severity', 'unknown').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Detectar si es escaneo LAN (IP/CIDR) para adaptar la UI
    target_type = detect_target_type(scan.get('target', ''))
    is_lan_scan = target_type in ('ip', 'cidr', 'range')

    # Para LAN scans, extraer info adicional del raw_results
    lan_info = {}
    if is_lan_scan and raw_results:
        lan_info['hosts'] = raw_results.get('hosts', [])
        lan_info['target_type'] = raw_results.get('target_type', target_type)
        # Contar puertos abiertos
        open_ports = 0
        for ip_data in raw_results.get('ports', {}).values():
            for host in ip_data.get('hosts', []):
                for port in host.get('ports', []):
                    if port.get('state') == 'open':
                        open_ports += 1
        lan_info['open_ports'] = open_ports

    return render_template('scan_detail.html',
                         scan=scan,
                         subdomains=subdomains,
                         services=services,
                         vulnerabilities=vulnerabilities_enriched,
                         raw_results=raw_results,
                         severity_counts=severity_counts,
                         is_lan_scan=is_lan_scan,
                         target_type=target_type,
                         lan_info=lan_info)

@app.route('/results')
def results():
    """Listado de todos los resultados"""
    scans = db.get_all_scans(limit=50)
    return render_template('results.html', scans=scans)

@app.route('/config')
def config_page():
    """Página de configuración"""
    return render_template('config.html')

# =============================
# RUTAS DE PREVIEW DE DASHBOARDS
# =============================

@app.route('/preview/cyber')
def preview_cyber():
    """Preview dashboard estilo Cyber/Hacker"""
    stats = db.get_stats()
    recent_scans = db.get_all_scans(limit=10)
    severity_stats = get_severity_statistics()
    return render_template('index_cyber.html',
                         stats=stats,
                         recent_scans=recent_scans,
                         severity_stats=severity_stats)

@app.route('/preview/minimal')
def preview_minimal():
    """Preview dashboard estilo Minimal/Professional"""
    stats = db.get_stats()
    recent_scans = db.get_all_scans(limit=10)
    severity_stats = get_severity_statistics()
    return render_template('index_minimal.html',
                         stats=stats,
                         recent_scans=recent_scans,
                         severity_stats=severity_stats)

@app.route('/preview/glass')
def preview_glass():
    """Preview dashboard estilo Glass/Modern"""
    stats = db.get_stats()
    recent_scans = db.get_all_scans(limit=10)
    severity_stats = get_severity_statistics()
    return render_template('index_glass.html',
                         stats=stats,
                         recent_scans=recent_scans,
                         severity_stats=severity_stats)

# =============================
# API REST
# =============================

@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    """Iniciar nuevo escaneo"""
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target es requerido'}), 400
    
    scan_id = f"{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    db.create_scan(scan_id, target, scan_type)
    db.update_scan_status(scan_id, 'running')
    
    thread = threading.Thread(
        target=run_scan_background,
        args=(scan_id, target, scan_type)
    )
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'message': 'Escaneo iniciado'
    })

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def api_scan_status(scan_id):
    """Obtener estado de un escaneo"""
    scan = db.get_scan(scan_id)
    
    if not scan:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    return jsonify(scan)

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def api_scan_results(scan_id):
    """Obtener resultados de un escaneo"""
    raw_results = db.get_raw_results(scan_id)
    
    if not raw_results:
        return jsonify({'error': 'Resultados no encontrados'}), 404
    
    return jsonify(raw_results)

@app.route('/api/scan/<scan_id>', methods=['DELETE'])
def api_scan_delete(scan_id):
    """Eliminar un escaneo"""
    success = db.delete_scan(scan_id)
    
    if not success:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    return jsonify({
        'success': True,
        'message': f'Escaneo {scan_id} eliminado correctamente'
    })

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Obtener estadísticas generales"""
    stats = db.get_stats()
    return jsonify(stats)

@app.route('/api/severity/stats', methods=['GET'])
def api_severity_stats():
    """Obtener estadísticas de severidad"""
    stats = get_severity_statistics()
    return jsonify(stats)

@app.route('/api/vuln/enrich/<cve_id>', methods=['GET'])
def api_enrich_vulnerability(cve_id):
    """
    Enriquecer una vulnerabilidad con datos de NVD
    """
    from utils.vuln_enricher import VulnEnricher

    enricher = VulnEnricher()
    data = enricher.enrich_cve(cve_id)

    if data:
        return jsonify({'success': True, 'data': data})
    else:
        return jsonify({'success': False, 'error': 'No se pudo enriquecer el CVE'}), 404

@app.route('/api/scan/<scan_id>/graph', methods=['GET'])
def api_scan_graph(scan_id):
    """
    Generar datos de grafo para visualización interactiva
    Retorna nodos y aristas en formato Cytoscape.js
    """
    scan = db.get_scan(scan_id)

    if not scan:
        return jsonify({'error': 'Escaneo no encontrado'}), 404

    # Obtener datos
    subdomains = db.get_subdomains(scan_id)
    services = db.get_services(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    raw_results = db.get_raw_results(scan_id)

    nodes = []
    edges = []

    # Nodo raíz: Target principal
    target = scan['target']
    nodes.append({
        'data': {
            'id': f'target_{target}',
            'label': target,
            'type': 'target',
            'size': 60
        }
    })

    # Mapeo de subdominios a IPs
    subdomain_to_ips = {}
    ip_to_ports = {}
    port_to_services = {}

    # Procesar servicios para mapear IPs → Puertos → Servicios
    for service in services:
        ip = service.get('ip', 'unknown')
        port = service.get('port', 0)
        protocol = service.get('protocol', 'tcp')
        port_id = f"{ip}:{port}/{protocol}"

        # Mapear IP a puertos
        if ip not in ip_to_ports:
            ip_to_ports[ip] = []
        if port_id not in ip_to_ports[ip]:
            ip_to_ports[ip].append(port_id)

        # Mapear puerto a servicio
        port_to_services[port_id] = service

    # Nodos: Subdominios
    for subdomain in subdomains:
        sub = subdomain.get('subdomain', '')
        subdomain_id = f'subdomain_{sub}'

        nodes.append({
            'data': {
                'id': subdomain_id,
                'label': sub,
                'type': 'subdomain',
                'is_alive': subdomain.get('is_alive', False),
                'http_status': subdomain.get('http_status'),
                'size': 40
            }
        })

        # Edge: Target → Subdomain
        edges.append({
            'data': {
                'source': f'target_{target}',
                'target': subdomain_id,
                'label': 'tiene'
            }
        })

    # Procesar URLs activas para mapear Subdominios → IPs
    if raw_results and 'alive_urls' in raw_results:
        for url_info in raw_results['alive_urls']:
            if isinstance(url_info, dict):
                host = url_info.get('host', '')
                # Intentar extraer IP si está disponible
                # (esto puede requerir resolución DNS, por ahora usamos host)
                subdomain_id = f'subdomain_{host}'

                # Si el subdominio existe, intentar asociarlo con IPs
                if any(s.get('subdomain') == host for s in subdomains):
                    # Buscar IP asociada en services
                    for service in services:
                        service_ip = service.get('ip', '')
                        if service_ip and service_ip not in subdomain_to_ips.get(host, []):
                            if host not in subdomain_to_ips:
                                subdomain_to_ips[host] = []
                            subdomain_to_ips[host].append(service_ip)

    # Detectar si es escaneo LAN
    from modules.network_utils import detect_target_type
    target_type_graph = detect_target_type(target)
    is_lan = target_type_graph in ('ip', 'cidr', 'range')

    # Nodos: IPs (deducidas de services)
    ip_set = set()
    for service in services:
        ip = service.get('ip', '')
        if ip and ip not in ip_set:
            ip_set.add(ip)
            nodes.append({
                'data': {
                    'id': f'ip_{ip}',
                    'label': ip,
                    'type': 'ip',
                    'size': 35
                }
            })

            # Para LAN: conectar Target → IP directamente
            if is_lan:
                edges.append({
                    'data': {
                        'source': f'target_{target}',
                        'target': f'ip_{ip}',
                        'label': 'host'
                    }
                })
            else:
                # Edge: Subdomain → IP (si hay mapeo, para domain scans)
                for sub, ips in subdomain_to_ips.items():
                    if ip in ips:
                        edges.append({
                            'data': {
                                'source': f'subdomain_{sub}',
                                'target': f'ip_{ip}',
                                'label': 'resuelve'
                            }
                        })

    # Nodos: Puertos
    for ip, ports in ip_to_ports.items():
        for port_id in ports:
            service = port_to_services.get(port_id, {})
            port_num = service.get('port', 0)
            protocol = service.get('protocol', 'tcp')

            nodes.append({
                'data': {
                    'id': f'port_{port_id}',
                    'label': f"{port_num}/{protocol}",
                    'type': 'port',
                    'port': port_num,
                    'protocol': protocol,
                    'size': 25
                }
            })

            # Edge: IP → Puerto
            edges.append({
                'data': {
                    'source': f'ip_{ip}',
                    'target': f'port_{port_id}',
                    'label': 'expone'
                }
            })

    # Nodos: Servicios
    for port_id, service in port_to_services.items():
        service_name = service.get('service', 'unknown')
        product = service.get('product', '')
        version = service.get('version', '')

        service_label = service_name
        if product:
            service_label = f"{product}"
            if version:
                service_label += f" {version}"

        service_id = f'service_{port_id}'

        nodes.append({
            'data': {
                'id': service_id,
                'label': service_label,
                'type': 'service',
                'service_name': service_name,
                'product': product,
                'version': version,
                'size': 30
            }
        })

        # Edge: Puerto → Servicio
        edges.append({
            'data': {
                'source': f'port_{port_id}',
                'target': service_id,
                'label': 'corre'
            }
        })

    # Nodos: Vulnerabilidades (CVEs)
    vuln_count = {}
    for vuln in vulnerabilities:
        cve = vuln.get('cve') or vuln.get('name', 'Unknown')
        severity = vuln.get('severity', 'info')
        target_url = vuln.get('target', '')

        # Crear ID único para el CVE
        cve_id = f'vuln_{cve.replace(" ", "_")}'

        # Contador de CVEs duplicados
        if cve not in vuln_count:
            vuln_count[cve] = 0
        vuln_count[cve] += 1

        # Agregar nodo de vulnerabilidad (solo una vez por CVE único)
        if vuln_count[cve] == 1:
            nodes.append({
                'data': {
                    'id': cve_id,
                    'label': cve,
                    'type': 'vulnerability',
                    'severity': severity,
                    'size': 35 if severity in ['critical', 'high'] else 25
                }
            })

        # Intentar conectar CVE con servicio/puerto afectado
        # Buscar en el target si coincide con alguna IP o host
        connected = False

        # Intentar conectar con servicios
        for port_id, service in port_to_services.items():
            service_id = f'service_{port_id}'
            ip = port_id.split(':')[0]

            # Si el target contiene la IP o coincide con el servicio
            if ip in target_url or service.get('product', '').lower() in vuln.get('name', '').lower():
                edges.append({
                    'data': {
                        'source': service_id,
                        'target': cve_id,
                        'label': 'afecta',
                        'severity': severity
                    }
                })
                connected = True
                break

        # Si no se conectó a servicio, conectar a target principal
        if not connected:
            edges.append({
                'data': {
                    'source': f'target_{target}',
                    'target': cve_id,
                    'label': 'afecta',
                    'severity': severity
                }
            })

    return jsonify({
        'success': True,
        'is_lan': is_lan,
        'elements': {
            'nodes': nodes,
            'edges': edges
        },
        'stats': {
            'total_nodes': len(nodes),
            'total_edges': len(edges),
            'subdomains': len([n for n in nodes if n['data']['type'] == 'subdomain']),
            'ips': len([n for n in nodes if n['data']['type'] == 'ip']),
            'ports': len([n for n in nodes if n['data']['type'] == 'port']),
            'services': len([n for n in nodes if n['data']['type'] == 'service']),
            'vulnerabilities': len([n for n in nodes if n['data']['type'] == 'vulnerability'])
        }
    })

# =============================
# EXPORTACIÓN
# =============================

@app.route('/api/scan/<scan_id>/export/<format>')
def api_export_scan(scan_id, format):
    """
    Exportar escaneo en diferentes formatos
    Formatos: pdf, excel, markdown, html
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        return jsonify({'error': 'Escaneo no encontrado'}), 404
    
    if format == 'pdf':
        return export_pdf(scan_id)
    elif format == 'excel':
        return export_excel(scan_id)
    elif format == 'markdown':
        return export_markdown(scan_id)
    elif format == 'html':
        return export_html(scan_id)
    else:
        return jsonify({'error': 'Formato no soportado'}), 400

@app.route('/api/health', methods=['GET'])
def api_health_check():
    """
    Health check del sistema
    Retorna estado del sistema y problemas detectados
    """
    try:
        auto_fix = request.args.get('auto_fix', 'false').lower() == 'true'

        health_check = SystemHealthCheck()
        results = health_check.run_full_check(auto_fix=auto_fix)

        # Determinar estado general
        has_critical = any(i['severity'] == 'CRITICAL' for i in results['issues'])
        has_errors = any(i['severity'] == 'ERROR' for i in results['issues'])

        if has_critical:
            status = 'CRITICAL'
        elif has_errors:
            status = 'ERROR'
        elif results['issues']:
            status = 'WARNING'
        else:
            status = 'OK'

        return jsonify({
            'status': status,
            'timestamp': results['timestamp'],
            'summary': {
                'total_issues': len(results['issues']),
                'critical': sum(1 for i in results['issues'] if i['severity'] == 'CRITICAL'),
                'errors': sum(1 for i in results['issues'] if i['severity'] == 'ERROR'),
                'warnings': sum(1 for i in results['issues'] if i['severity'] == 'WARNING'),
                'actions_taken': len(results['actions_taken'])
            },
            'details': results
        })

    except Exception as e:
        return jsonify({
            'status': 'ERROR',
            'error': str(e)
        }), 500

# =============================
# WEBSOCKET EVENTS
# =============================

@socketio.on('connect')
def handle_connect():
    """Cliente conectado"""
    print('[WebSocket] Cliente conectado')
    emit('connected', {'data': 'Conectado a FAROSINT'})

@socketio.on('disconnect')
def handle_disconnect():
    """Cliente desconectado"""
    print('[WebSocket] Cliente desconectado')

# =============================
# FUNCIONES AUXILIARES
# =============================

def run_scan_background(scan_id, target, scan_type):
    """Ejecutar escaneo en background con enriquecimiento"""
    global current_orchestrator

    try:
        # Callback para reportar progreso
        def progress_callback(phase, percent, message):
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'phase': phase,
                'percent': percent,
                'message': message
            })

        current_orchestrator = FAROSINTOrchestrator(progress_callback=progress_callback)

        socketio.emit('scan_started', {
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type
        })

        # Ejecutar escaneo
        results = current_orchestrator.scan(target, scan_type=scan_type)
        
        # Guardar resultados en BD
        db.save_raw_results(scan_id, results)
        
        # Guardar subdominios
        alive_urls_dict = {}
        if 'alive_urls' in results:
            for url_info in results['alive_urls']:
                if isinstance(url_info, dict) and 'host' in url_info:
                    host = url_info.get('host', '')
                    alive_urls_dict[host] = url_info.get('status_code', 200)
        
        for subdomain in results.get('subdomains', []):
            is_alive = subdomain in alive_urls_dict
            http_status = alive_urls_dict.get(subdomain, None)
            
            db.add_subdomain(
                scan_id,
                subdomain,
                'scan',
                is_alive=is_alive,
                http_status=http_status
            )
        
        # Guardar servicios
        for ip, port_data in results.get('ports', {}).items():
            hosts_data = port_data.get('hosts', [])
            for host in hosts_data:
                for port in host.get('ports', []):
                    # Solo guardar puertos abiertos o filtrados (no cerrados)
                    state = port.get('state', 'open')
                    if state in ('open', 'filtered', 'open|filtered'):
                        db.add_service(
                            scan_id,
                            host.get('ip', ip),
                            port['port'],
                            port.get('protocol', 'tcp'),
                            port.get('service'),
                            port.get('product'),
                            port.get('version')
                        )
        
        # Guardar vulnerabilidades CON ENRIQUECIMIENTO
        for vuln in results.get('vulnerabilities', []):
            # El módulo vulnerability_scan ya enriquece las vulns
            add_vulnerability_enriched(scan_id, vuln)
        
        # Actualizar estado
        db.update_scan_status(scan_id, 'completed', datetime.now())
        
        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'results': {
                'subdomains': len(results.get('subdomains', [])),
                'urls': len(results.get('alive_urls', [])),
                'vulnerabilities': len(results.get('vulnerabilities', []))
            }
        })
    
    except Exception as e:
        print(f"[Error] Escaneo fallido: {str(e)}")
        import traceback
        traceback.print_exc()
        db.update_scan_status(scan_id, 'failed', datetime.now())
        socketio.emit('scan_failed', {
            'scan_id': scan_id,
            'error': str(e)
        })
    
    finally:
        if current_orchestrator:
            current_orchestrator.shutdown()
            current_orchestrator = None

def add_vulnerability_enriched(scan_id, vuln):
    """
    Guardar vulnerabilidad con enriquecimiento MITRE/OWASP/CVE
    
    Args:
        scan_id: ID del escaneo
        vuln: Dict con info de vulnerabilidad (ya enriquecida por vulnerability_scan.py)
    """
    import sqlite3
    
    conn = sqlite3.connect(str(Path.home() / "FAROSINT" / "gui" / "farosint.db"))
    cursor = conn.cursor()
    
    # Extraer campos básicos
    name = vuln.get('name', 'Unknown')
    severity = vuln.get('severity', 'unknown')
    host = vuln.get('host', vuln.get('matched_at', ''))
    template = vuln.get('template', '')
    cve = vuln.get('cve')
    cvss_score = vuln.get('cvss_score', 0.0)

    # Descripción compuesta con tags y referencias
    tags = vuln.get('tags', [])
    references = vuln.get('references', {})
    remediation = vuln.get('remediation', {})

    description_parts = []
    if tags:
        description_parts.append(f"Tags: {', '.join(tags)}")
    if references:
        refs_text = ', '.join([f"{k}: {v}" for k, v in references.items() if v])
        if refs_text:
            description_parts.append(f"Referencias: {refs_text}")
    if remediation and remediation.get('steps'):
        description_parts.append(f"Remediación: {'; '.join(remediation.get('steps', []))}")

    description = '\n'.join(description_parts) if description_parts else ''

    # Insertar usando solo las columnas que existen en la tabla
    cursor.execute("""
        INSERT INTO vulnerabilities (
            scan_id, target, name, severity, template_id, description,
            matched_at, cve, cvss
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, host, name, severity, template, description,
        host, cve, cvss_score
    ))
    
    conn.commit()
    conn.close()

def extract_mitre_technique(url):
    """Extraer técnica MITRE de URL"""
    if not url:
        return ''
    # https://attack.mitre.org/techniques/T1190/ → T1190
    parts = url.rstrip('/').split('/')
    for part in parts:
        if part.startswith('T'):
            return part
    return ''

def extract_owasp_category(url):
    """Extraer categoría OWASP de URL"""
    if not url:
        return ''
    # https://owasp.org/Top10/A03_2021-Injection/ → A03:2021
    parts = url.rstrip('/').split('/')
    for part in parts:
        if part.startswith('A') and '_' in part:
            # A03_2021-Injection → A03:2021
            code = part.split('_')[0]
            year = part.split('_')[1].split('-')[0]
            return f"{code}:{year}"
    return ''

def get_severity_statistics():
    """Obtener estadísticas de severidad para gráficos"""
    import sqlite3
    
    conn = sqlite3.connect(str(Path.home() / "FAROSINT" / "gui" / "farosint.db"))
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY severity
        ORDER BY 
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """)
    
    results = cursor.fetchall()
    conn.close()
    
    stats = {
        'labels': [],
        'data': [],
        'colors': [],
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }

    color_map = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#17a2b8',
        'info': '#6c757d'
    }

    for severity, count in results:
        stats['labels'].append(severity.upper())
        stats['data'].append(count)
        stats['colors'].append(color_map.get(severity, '#6c757d'))
        # Agregar contadores individuales
        if severity in stats:
            stats[severity] = count

    return stats

def export_markdown(scan_id):
    """Exportar escaneo a Markdown"""
    scan = db.get_scan(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    
    md_content = f"""# FAROSINT Security Report

## Scan Information
- **Target:** {scan['target']}
- **Scan ID:** {scan['scan_id']}
- **Date:** {scan['started_at']}
- **Status:** {scan['status']}

## Executive Summary
Total vulnerabilities found: {len(vulnerabilities)}

"""
    
    # Agrupar por severidad
    by_severity = {}
    for vuln in vulnerabilities:
        sev = vuln['severity']
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(vuln)
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in by_severity:
            md_content += f"\n### {severity.upper()} ({len(by_severity[severity])})\n\n"
            for vuln in by_severity[severity]:
                md_content += f"#### {vuln['name']}\n"
                md_content += f"- **Host:** {vuln['target']}\n"
                
                if vuln.get('cve'):
                    md_content += f"- **CVE:** {vuln['cve']}\n"
                
                if vuln.get('cvss_score'):
                    md_content += f"- **CVSS Score:** {vuln['cvss_score']}\n"
                
                if vuln.get('mitre_url'):
                    md_content += f"- **MITRE ATT&CK:** [{vuln.get('mitre_technique', 'Link')}]({vuln['mitre_url']})\n"
                
                if vuln.get('owasp_url'):
                    md_content += f"- **OWASP:** [{vuln.get('owasp_category', 'Link')}]({vuln['owasp_url']})\n"
                
                if vuln.get('remediation_priority'):
                    md_content += f"- **Remediation Priority:** {vuln['remediation_priority']}\n"
                
                md_content += "\n"
    
    # Crear archivo en memoria
    buffer = io.BytesIO()
    buffer.write(md_content.encode('utf-8'))
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='text/markdown',
        as_attachment=True,
        download_name=f'farosint_report_{scan_id}.md'
    )

def export_excel(scan_id):
    """Exportar escaneo a Excel (placeholder)"""
    # TODO: Implementar con openpyxl
    return jsonify({'error': 'Excel export en desarrollo'}), 501

def export_pdf(scan_id):
    """Exportar escaneo a PDF profesional con reportlab"""
    try:
        # Obtener datos del escaneo
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({'error': 'Escaneo no encontrado'}), 404

        # Obtener todos los datos necesarios
        subdomains = db.get_subdomains(scan_id)
        services = db.get_services(scan_id)
        vulnerabilities = db.get_vulnerabilities(scan_id)
        raw_results = db.get_raw_results(scan_id)

        # Preparar datos para el PDF
        scan_data = {
            'scan_id': scan.get('scan_id'),
            'target': scan.get('target'),
            'scan_type': scan.get('scan_type'),
            'status': scan.get('status'),
            'start_time': scan.get('start_time'),
            'end_time': scan.get('end_time'),
            'subdomains': subdomains,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'raw_results': raw_results
        }

        # Generar PDF
        pdf_path = generate_pdf_report(scan_data)

        # Enviar archivo PDF
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'FAROSINT_Report_{scan_id}.pdf'
        )

    except Exception as e:
        print(f"[PDF Export] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Error generando PDF: {str(e)}'}), 500

def export_html(scan_id):
    """Exportar escaneo a HTML standalone"""
    scan = db.get_scan(scan_id)
    vulnerabilities = db.get_vulnerabilities(scan_id)
    
    # Renderizar template y retornar como descarga
    html = render_template('export_standalone.html',
                          scan=scan,
                          vulnerabilities=vulnerabilities)
    
    buffer = io.BytesIO()
    buffer.write(html.encode('utf-8'))
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='text/html',
        as_attachment=True,
        download_name=f'farosint_report_{scan_id}.html'
    )

# =============================
# FILTROS JINJA2
# =============================

@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Formatear datetime"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except:
            return value
    if value:
        return value.strftime(format)
    return ''

@app.template_filter('severity_badge')
def severity_badge(severity):
    """Generar badge HTML para severidad"""
    styles = {
        'critical': ('danger',    'white'),
        'high':     ('warning',   'dark'),
        'medium':   ('info',      'white'),
        'low':      ('secondary', 'white'),
        'info':     ('light',     'dark'),
    }
    bg, text = styles.get(severity.lower(), ('secondary', 'white'))
    return f'<span class="badge bg-{bg} text-{text}">{severity.upper()}</span>'

# =============================
# HEALTH CHECK BACKGROUND JOB
# =============================

def health_check_worker():
    """Worker que ejecuta health check periódicamente"""
    import time

    print("[Health Check] Worker iniciado - ejecutando cada 10 minutos")

    while True:
        try:
            time.sleep(600)  # 10 minutos

            print(f"\n[Health Check] Ejecutando verificación automática...")
            health_check = SystemHealthCheck()
            results = health_check.run_full_check(auto_fix=True)

            # Si hay problemas críticos, emitir alerta via SocketIO
            critical_issues = [i for i in results['issues'] if i['severity'] == 'CRITICAL']
            if critical_issues:
                socketio.emit('system_alert', {
                    'severity': 'CRITICAL',
                    'message': f"{len(critical_issues)} problema(s) crítico(s) detectado(s)",
                    'issues': critical_issues
                })

        except Exception as e:
            print(f"[Health Check] Error en worker: {e}")

# Iniciar worker en background
health_check_thread = threading.Thread(target=health_check_worker, daemon=True)
health_check_thread.start()

# =============================
# MAIN
# =============================

if __name__ == '__main__':
    print("="*60)
    print("  FAROSINT Dashboard - MEJORADO")
    print("="*60)
    print(f"  URL: http://localhost:5000")
    print("  Características:")
    print("    - MITRE ATT&CK integration")
    print("    - OWASP Top 10 references")
    print("    - CVE Details links")
    print("    - CVSS scoring")
    print("    - Remediation steps")
    print("    - Export to Markdown/HTML")
    print("="*60)
    print()
    
    socketio.run(app,
                host='0.0.0.0',
                port=5000,
                debug=True,
                allow_unsafe_werkzeug=True)
