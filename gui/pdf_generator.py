"""
FAROSINT PDF Report Generator
Genera reportes profesionales en PDF con gráficos y tablas
"""

import io
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

import matplotlib
matplotlib.use('Agg')  # Backend sin GUI
import matplotlib.pyplot as plt
from io import BytesIO


class FAROSINTPDFReport:
    """Generador de reportes PDF profesionales para FAROSINT"""

    def __init__(self, scan_data: Dict[str, Any], output_path: Optional[str] = None):
        """
        Inicializar generador de PDF

        Args:
            scan_data: Diccionario con datos del escaneo
            output_path: Ruta donde guardar el PDF (opcional)
        """
        self.scan_data = scan_data
        self.output_path = output_path or f"/tmp/farosint_report_{scan_data['scan_id']}.pdf"

        # Configuración de página
        self.page_size = A4
        self.width, self.height = self.page_size

        # Estilos
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

        # Colores corporativos
        self.color_primary = colors.HexColor('#0d6efd')
        self.color_danger = colors.HexColor('#dc3545')
        self.color_warning = colors.HexColor('#ffc107')
        self.color_success = colors.HexColor('#198754')
        self.color_gray = colors.HexColor('#6c757d')

        # Contenido del PDF
        self.story = []

    def _setup_custom_styles(self):
        """Configurar estilos personalizados"""
        # Título principal
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#0d6efd'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Subtítulo
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#212529'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Sección
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0d6efd'),
            spaceAfter=10,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.HexColor('#0d6efd'),
            borderPadding=5,
            backColor=colors.HexColor('#e7f3ff')
        ))

        # Texto normal justificado
        self.styles.add(ParagraphStyle(
            name='Justified',
            parent=self.styles['BodyText'],
            alignment=TA_JUSTIFY,
            fontSize=10,
            leading=14
        ))

        # Texto destacado
        self.styles.add(ParagraphStyle(
            name='Highlight',
            parent=self.styles['BodyText'],
            fontSize=11,
            textColor=colors.HexColor('#dc3545'),
            fontName='Helvetica-Bold'
        ))

    def generate(self) -> str:
        """
        Generar PDF completo

        Returns:
            Ruta del archivo PDF generado
        """
        # Crear documento
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=self.page_size,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Construir contenido
        self._build_cover_page()
        self._build_executive_summary()
        self._build_statistics_section()
        self._build_subdomains_section()
        self._build_services_section()
        self._build_vulnerabilities_section()
        self._build_conclusions()

        # Generar PDF
        doc.build(self.story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)

        return self.output_path

    def _add_page_number(self, canvas_obj, doc):
        """Agregar número de página al footer"""
        page_num = canvas_obj.getPageNumber()
        text = f"Página {page_num}"
        canvas_obj.saveState()
        canvas_obj.setFont('Helvetica', 9)
        canvas_obj.setFillColor(colors.gray)
        canvas_obj.drawRightString(self.width - 72, 30, text)
        canvas_obj.drawString(72, 30, "FAROSINT Report")
        canvas_obj.restoreState()

    def _build_cover_page(self):
        """Construir portada del reporte"""
        # Espaciador inicial
        self.story.append(Spacer(1, 0.8*inch))

        # Intentar cargar logo si existe
        logo_path = os.path.join(os.path.dirname(__file__), 'static', 'img', 'logo.png')
        if not os.path.exists(logo_path):
            # Buscar alternativas
            logo_path = os.path.join(os.path.dirname(__file__), 'static', 'img', 'farosint.png')

        if os.path.exists(logo_path):
            try:
                logo_img = Image(logo_path, width=2*inch, height=2*inch)
                self.story.append(logo_img)
                self.story.append(Spacer(1, 0.3*inch))
            except:
                pass  # Si falla, continuar sin logo

        # Título principal (sin recuadro)
        title = Paragraph("FAROSINT", self.styles['CustomTitle'])
        self.story.append(title)

        # Subtítulo
        subtitle = Paragraph(
            "Framework Avanzado de Reconocimiento OSINT",
            self.styles['CustomHeading2']
        )
        self.story.append(subtitle)

        self.story.append(Spacer(1, 0.5*inch))

        # Información del escaneo
        scan_info = [
            ['Target:', self.scan_data.get('target', 'N/A')],
            ['Tipo de Escaneo:', self.scan_data.get('scan_type', 'N/A').upper()],
            ['Fecha:', self.scan_data.get('start_time', 'N/A')],
            ['Scan ID:', self.scan_data.get('scan_id', 'N/A')],
            ['Estado:', self.scan_data.get('status', 'N/A').upper()]
        ]

        table = Table(scan_info, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e7f3ff')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#0d6efd')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray)
        ]))

        self.story.append(table)
        self.story.append(Spacer(1, 1*inch))

        # Disclaimer
        disclaimer = Paragraph(
            "<i>Este reporte contiene información de reconocimiento OSINT sobre el objetivo especificado. "
            "La información presentada es solo para uso autorizado en auditorías de seguridad.</i>",
            self.styles['Justified']
        )
        self.story.append(disclaimer)

        # Salto de página
        self.story.append(PageBreak())

    def _build_executive_summary(self):
        """Construir resumen ejecutivo"""
        # Título de sección
        title = Paragraph("Resumen Ejecutivo", self.styles['SectionTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))

        # Extraer métricas
        subdomains_count = len(self.scan_data.get('subdomains', []))
        services_count = len(self.scan_data.get('services', []))
        vulnerabilities = self.scan_data.get('vulnerabilities', [])
        vulns_count = len(vulnerabilities)

        # Contar por severidad
        critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
        medium_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'medium')
        low_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'low')

        # Extractar IPs únicas
        ips = set()
        for subdomain in self.scan_data.get('subdomains', []):
            if subdomain.get('ip'):
                ips.add(subdomain['ip'])
        ips_count = len(ips)

        # Texto del resumen
        summary_text = f"""
        El escaneo OSINT realizado sobre <b>{self.scan_data.get('target', 'N/A')}</b> ha identificado
        <b>{subdomains_count} subdominios</b>, <b>{ips_count} direcciones IP únicas</b>, y
        <b>{services_count} servicios activos</b>.
        <br/><br/>
        Se detectaron un total de <b>{vulns_count} vulnerabilidades</b>, de las cuales
        <font color="#c0392b"><b>{critical_count} son críticas</b></font>,
        <font color="#e74c3c"><b>{high_count} son altas</b></font>,
        <font color="#f39c12"><b>{medium_count} son medias</b></font>, y
        <font color="#f1c40f"><b>{low_count} son bajas</b></font>.
        """

        if critical_count > 0 or high_count > 0:
            summary_text += """
            <br/><br/>
            <font color="#dc3545"><b>⚠ ATENCIÓN:</b> Se encontraron vulnerabilidades críticas y/o altas que requieren
            atención inmediata. Consulte la sección de vulnerabilidades para más detalles.</font>
            """

        summary = Paragraph(summary_text, self.styles['Justified'])
        self.story.append(summary)

        self.story.append(Spacer(1, 0.3*inch))

        # Tabla de métricas clave
        metrics_title = Paragraph("<b>Métricas Clave</b>", self.styles['Heading3'])
        self.story.append(metrics_title)
        self.story.append(Spacer(1, 0.1*inch))

        metrics_data = [
            ['Métrica', 'Valor'],
            ['Subdominios Descubiertos', str(subdomains_count)],
            ['IPs Únicas', str(ips_count)],
            ['Servicios Activos', str(services_count)],
            ['Total Vulnerabilidades', str(vulns_count)],
            ['Vulnerabilidades Críticas', str(critical_count)],
            ['Vulnerabilidades Altas', str(high_count)]
        ]

        metrics_table = Table(metrics_data, colWidths=[3*inch, 1.5*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.color_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))

        self.story.append(metrics_table)
        self.story.append(Spacer(1, 0.3*inch))

        # Gráfico de vulnerabilidades por severidad
        if vulns_count > 0:
            chart_img = self._create_vulnerability_chart(critical_count, high_count, medium_count, low_count)
            if chart_img:
                self.story.append(Paragraph("<b>Distribución de Vulnerabilidades por Severidad</b>", self.styles['Heading3']))
                self.story.append(Spacer(1, 0.1*inch))
                self.story.append(chart_img)

        self.story.append(PageBreak())

    def _create_vulnerability_chart(self, critical, high, medium, low):
        """Crear gráfico de vulnerabilidades con matplotlib"""
        try:
            fig, ax = plt.subplots(figsize=(6, 4))

            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            counts = [critical, high, medium, low]
            colors_list = ['#c0392b', '#e74c3c', '#f39c12', '#f1c40f']

            # Filtrar solo severidades con valores > 0
            filtered_data = [(s, c, col) for s, c, col in zip(severities, counts, colors_list) if c > 0]

            if not filtered_data:
                return None

            severities_filtered, counts_filtered, colors_filtered = zip(*filtered_data)

            ax.bar(severities_filtered, counts_filtered, color=colors_filtered, edgecolor='black', linewidth=1.2)
            ax.set_xlabel('Severidad', fontsize=11, fontweight='bold')
            ax.set_ylabel('Cantidad', fontsize=11, fontweight='bold')
            ax.set_title('Vulnerabilidades por Severidad', fontsize=13, fontweight='bold')
            ax.grid(axis='y', alpha=0.3)

            # Agregar valores en las barras
            for i, (sev, count) in enumerate(zip(severities_filtered, counts_filtered)):
                ax.text(i, count + 0.5, str(count), ha='center', va='bottom', fontweight='bold', fontsize=10)

            # Guardar gráfico en buffer
            buf = BytesIO()
            plt.tight_layout()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            buf.seek(0)
            plt.close(fig)

            # Crear imagen para ReportLab
            img = Image(buf, width=5*inch, height=3.3*inch)
            return img

        except Exception as e:
            print(f"[PDF] Error creating vulnerability chart: {e}")
            return None

    def _build_statistics_section(self):
        """Construir sección de estadísticas"""
        title = Paragraph("Estadísticas Detalladas", self.styles['SectionTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))

        # Estadísticas de subdominios
        subdomains = self.scan_data.get('subdomains', [])
        alive_count = sum(1 for s in subdomains if s.get('is_alive'))

        stats_text = f"""
        <b>Subdominios:</b> Se descubrieron {len(subdomains)} subdominios, de los cuales {alive_count} están activos (responden HTTP/HTTPS).
        <br/><br/>
        <b>Servicios:</b> Se identificaron {len(self.scan_data.get('services', []))} servicios en ejecución.
        """

        stats = Paragraph(stats_text, self.styles['Justified'])
        self.story.append(stats)

        self.story.append(Spacer(1, 0.3*inch))

    def _build_subdomains_section(self):
        """Construir sección de subdominios"""
        title = Paragraph("Subdominios Descubiertos", self.styles['SectionTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))

        subdomains = self.scan_data.get('subdomains', [])

        if not subdomains:
            no_data = Paragraph("<i>No se encontraron subdominios.</i>", self.styles['BodyText'])
            self.story.append(no_data)
            return

        # Limitar a primeros 50 subdominios
        subdomains_to_show = subdomains[:50]

        # Tabla de subdominios
        data = [['Subdominio', 'IP', 'Estado']]

        for subdomain in subdomains_to_show:
            name = subdomain.get('subdomain', 'N/A')
            ip = subdomain.get('ip', '-')
            is_alive = '✓ Activo' if subdomain.get('is_alive') else '✗ Inactivo'

            data.append([name, ip, is_alive])

        if len(subdomains) > 50:
            data.append([f'... y {len(subdomains) - 50} más', '', ''])

        table = Table(data, colWidths=[3*inch, 1.8*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.color_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))

        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(PageBreak())

    def _build_services_section(self):
        """Construir sección de servicios"""
        title = Paragraph("Servicios Detectados", self.styles['SectionTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))

        services = self.scan_data.get('services', [])

        if not services:
            no_data = Paragraph("<i>No se detectaron servicios.</i>", self.styles['BodyText'])
            self.story.append(no_data)
            return

        # Limitar a primeros 30 servicios
        services_to_show = services[:30]

        # Tabla de servicios
        data = [['Host', 'Puerto', 'Servicio', 'Versión']]

        for service in services_to_show:
            host = service.get('host', 'N/A')
            port = str(service.get('port', 'N/A'))
            name = service.get('service', 'unknown')
            product = service.get('product', '')
            version = service.get('version', '')

            version_str = f"{product} {version}".strip() if product or version else '-'

            data.append([host, port, name, version_str])

        if len(services) > 30:
            data.append([f'... y {len(services) - 30} más', '', '', ''])

        table = Table(data, colWidths=[2*inch, 0.8*inch, 1.5*inch, 2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.color_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))

        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(PageBreak())

    def _build_vulnerabilities_section(self):
        """Construir sección de vulnerabilidades"""
        title = Paragraph("Vulnerabilidades Identificadas", self.styles['SectionTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))

        vulnerabilities = self.scan_data.get('vulnerabilities', [])

        if not vulnerabilities:
            no_vulns = Paragraph(
                "<font color='#198754'><b>✓ No se encontraron vulnerabilidades. El objetivo presenta un buen nivel de seguridad.</b></font>",
                self.styles['BodyText']
            )
            self.story.append(no_vulns)
            return

        # Ordenar por severidad (CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        vulnerabilities_sorted = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get('severity', 'unknown').lower(), 5)
        )

        # Mostrar primeras 30 vulnerabilidades
        vulns_to_show = vulnerabilities_sorted[:30]

        # Tabla de vulnerabilidades
        data = [['CVE / ID', 'Severidad', 'CVSS', 'Descripción']]

        for vuln in vulns_to_show:
            cve_id = vuln.get('cve_id') or vuln.get('name', 'N/A')
            severity = vuln.get('severity', 'unknown').upper()
            cvss = str(vuln.get('cvss_score', '-'))
            description = vuln.get('description', 'Sin descripción')

            # Truncar descripción
            if len(description) > 100:
                description = description[:97] + '...'

            # Color por severidad
            if severity == 'CRITICAL':
                severity_cell = Paragraph(f"<font color='#c0392b'><b>{severity}</b></font>", self.styles['BodyText'])
            elif severity == 'HIGH':
                severity_cell = Paragraph(f"<font color='#e74c3c'><b>{severity}</b></font>", self.styles['BodyText'])
            elif severity == 'MEDIUM':
                severity_cell = Paragraph(f"<font color='#f39c12'><b>{severity}</b></font>", self.styles['BodyText'])
            else:
                severity_cell = severity

            data.append([cve_id, severity_cell, cvss, description])

        if len(vulnerabilities) > 30:
            data.append([f'... y {len(vulnerabilities) - 30} más', '', '', ''])

        table = Table(data, colWidths=[1.5*inch, 1*inch, 0.6*inch, 3.2*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.color_danger),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))

        self.story.append(table)
        self.story.append(Spacer(1, 0.3*inch))
        self.story.append(PageBreak())

    def _build_conclusions(self):
        """Construir sección de conclusiones"""
        title = Paragraph("Conclusiones y Recomendaciones", self.styles['SectionTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.2*inch))

        vulnerabilities = self.scan_data.get('vulnerabilities', [])
        critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')

        if critical_count > 0 or high_count > 0:
            conclusion_text = f"""
            El análisis de seguridad reveló <b>{critical_count} vulnerabilidades críticas</b> y
            <b>{high_count} vulnerabilidades altas</b> que representan un riesgo significativo para la seguridad del objetivo.
            <br/><br/>
            <b>Recomendaciones Prioritarias:</b>
            <br/>
            1. <b>Remediar inmediatamente</b> todas las vulnerabilidades críticas identificadas.<br/>
            2. Aplicar parches de seguridad y actualizaciones de software.<br/>
            3. Realizar análisis de configuración de servicios expuestos.<br/>
            4. Implementar monitoreo continuo de la superficie de ataque.<br/>
            5. Establecer un programa de gestión de vulnerabilidades.<br/>
            <br/>
            <font color="#dc3545"><b>Nivel de Riesgo: ALTO</b></font>
            """
        elif len(vulnerabilities) > 0:
            conclusion_text = """
            El análisis identificó vulnerabilidades de severidad media y baja. Aunque no representan un riesgo inmediato,
            se recomienda su remediación en el marco de un programa de gestión de vulnerabilidades.
            <br/><br/>
            <b>Recomendaciones:</b>
            <br/>
            1. Planificar la remediación de vulnerabilidades identificadas.<br/>
            2. Mantener actualizados los sistemas y servicios.<br/>
            3. Implementar pruebas de seguridad periódicas.<br/>
            <br/>
            <font color="#f39c12"><b>Nivel de Riesgo: MEDIO</b></font>
            """
        else:
            conclusion_text = """
            El escaneo no identificó vulnerabilidades conocidas en la superficie de ataque analizada.
            El objetivo presenta un nivel de seguridad aceptable.
            <br/><br/>
            <b>Recomendaciones:</b>
            <br/>
            1. Mantener el nivel actual de seguridad con actualizaciones regulares.<br/>
            2. Implementar pruebas de seguridad periódicas.<br/>
            3. Monitorear continuamente la superficie de ataque.<br/>
            <br/>
            <font color="#198754"><b>Nivel de Riesgo: BAJO</b></font>
            """

        conclusion = Paragraph(conclusion_text, self.styles['Justified'])
        self.story.append(conclusion)

        self.story.append(Spacer(1, 0.5*inch))

        # Footer del reporte
        footer_text = f"""
        <br/><br/>
        <i>Reporte generado automáticamente por FAROSINT el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>
        <br/>
        <i>Scan ID: {self.scan_data.get('scan_id', 'N/A')}</i>
        """
        footer = Paragraph(footer_text, self.styles['BodyText'])
        self.story.append(footer)


def generate_pdf_report(scan_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """
    Función de utilidad para generar reporte PDF

    Args:
        scan_data: Diccionario con datos del escaneo
        output_path: Ruta donde guardar el PDF (opcional)

    Returns:
        Ruta del archivo PDF generado
    """
    generator = FAROSINTPDFReport(scan_data, output_path)
    return generator.generate()
