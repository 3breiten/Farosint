# Visualización de Grafo Interactivo

## Descripción General

La visualización de grafo interactivo es una característica avanzada de FAROSINT que permite explorar visualmente las relaciones entre todas las entidades descubiertas durante un escaneo OSINT. Utiliza Cytoscape.js para renderizar un grafo interactivo y navegable que muestra cómo se conectan dominios, subdominios, IPs, puertos, servicios y vulnerabilidades.

## Acceso

1. Realizar un escaneo de un dominio objetivo
2. Navegar a la página de detalles del escaneo
3. Seleccionar la pestaña **"Grafo Interactivo"**

## Arquitectura Técnica

### Stack Tecnológico

- **Frontend:** Cytoscape.js 3.28.1 (biblioteca de visualización de grafos)
- **Backend:** Flask REST API
- **Formato de datos:** JSON compatible con Cytoscape.js
- **Algoritmo de layout:** COSE (Compound Spring Embedder)

### Flujo de Datos

```
1. Usuario accede a pestaña "Grafo Interactivo"
2. JavaScript hace fetch a /api/scan/<scan_id>/graph
3. Backend consulta SQLite y genera estructura de grafo
4. Frontend recibe JSON con nodes y edges
5. Cytoscape.js renderiza el grafo con estilos y layout
6. Usuario interactúa con controles, filtros y búsqueda
```

## Estructura de Datos

### Endpoint API

**URL:** `GET /api/scan/<scan_id>/graph`

**Respuesta:**
```json
{
  "success": true,
  "elements": {
    "nodes": [
      {
        "data": {
          "id": "target-example.com",
          "label": "example.com",
          "type": "target"
        },
        "classes": "target"
      },
      {
        "data": {
          "id": "subdomain-123",
          "label": "www.example.com",
          "type": "subdomain",
          "ip": "93.184.216.34"
        },
        "classes": "subdomain"
      }
    ],
    "edges": [
      {
        "data": {
          "source": "target-example.com",
          "target": "subdomain-123",
          "label": "has_subdomain"
        }
      }
    ]
  },
  "stats": {
    "total_nodes": 150,
    "total_edges": 200,
    "node_types": {
      "target": 1,
      "subdomain": 25,
      "ip": 15,
      "port": 50,
      "service": 40,
      "cve": 19
    },
    "edge_types": {
      "has_subdomain": 25,
      "resolves_to": 25,
      "has_port": 50,
      "runs_service": 40,
      "has_vulnerability": 19
    }
  }
}
```

## Tipos de Nodos

### 1. Target (Objetivo)
- **Representación:** Triángulo rojo grande
- **Color:** #dc3545 (rojo Bootstrap)
- **Tamaño:** 50px
- **Datos:** Domain target del escaneo
- **Relaciones salientes:** Subdominios descubiertos

### 2. Subdomain (Subdominio)
- **Representación:** Círculo azul mediano
- **Color:** #0d6efd (azul Bootstrap)
- **Tamaño:** 40px
- **Datos:** Nombre del subdominio, IP resuelta
- **Relaciones entrantes:** Target
- **Relaciones salientes:** IPs a las que resuelve

### 3. IP (Dirección IP)
- **Representación:** Rectángulo verde mediano
- **Color:** #198754 (verde Bootstrap)
- **Tamaño:** 35px
- **Datos:** Dirección IP
- **Relaciones entrantes:** Subdominios
- **Relaciones salientes:** Puertos abiertos

### 4. Port (Puerto)
- **Representación:** Rectángulo naranja pequeño
- **Color:** #fd7e14 (naranja Bootstrap)
- **Tamaño:** 30px
- **Datos:** Número de puerto, estado (open/closed/filtered)
- **Relaciones entrantes:** IPs
- **Relaciones salientes:** Servicios corriendo en el puerto

### 5. Service (Servicio)
- **Representación:** Elipse morada pequeña
- **Color:** #6f42c1 (morado Bootstrap)
- **Tamaño:** 30px
- **Datos:** Nombre del servicio, producto, versión
- **Relaciones entrantes:** Puertos
- **Relaciones salientes:** Vulnerabilidades (CVEs)

### 6. CVE (Vulnerabilidad)
- **Representación:** Diamante con color según severidad
- **Colores:**
  - **CRITICAL:** #721c24 (rojo oscuro)
  - **HIGH:** #fd7e14 (naranja)
  - **MEDIUM:** #ffc107 (amarillo)
  - **LOW:** #17a2b8 (azul claro)
- **Tamaño:** 35px
- **Datos:** CVE ID, severidad, CVSS score, descripción
- **Relaciones entrantes:** Servicios vulnerables

## Tipos de Relaciones (Edges)

Todas las relaciones son dirigidas (tienen origen y destino).

| Tipo | Label | Source | Target | Descripción |
|------|-------|--------|--------|-------------|
| `has_subdomain` | has subdomain | Target | Subdomain | El dominio tiene este subdominio |
| `resolves_to` | resolves to | Subdomain | IP | El subdominio resuelve a esta IP |
| `has_port` | has port | IP | Port | La IP tiene este puerto abierto |
| `runs_service` | runs service | Port | Service | El puerto corre este servicio |
| `has_vulnerability` | vulnerable to | Service | CVE | El servicio tiene esta vulnerabilidad |

## Controles de Usuario

### Controles Principales

#### 1. Reset
- **Función:** Reinicia la posición y zoom del grafo
- **Uso:** Click en botón "Reset"
- **Efecto:** Vuelve a la vista inicial con todos los nodos visibles

#### 2. Fit
- **Función:** Ajusta automáticamente el zoom y posición para mostrar todos los elementos visibles
- **Uso:** Click en botón "Fit"
- **Efecto:** Centra el grafo y ajusta el zoom óptimo

#### 3. Export PNG
- **Función:** Exporta el grafo actual como imagen PNG de alta resolución
- **Uso:** Click en botón "Export PNG"
- **Formato:** PNG con 2x pixel ratio para calidad HD
- **Nombre archivo:** `graph-export-<timestamp>.png`

### Filtros Dinámicos

Los filtros permiten mostrar/ocultar tipos específicos de nodos y sus relaciones asociadas.

#### Filtro Subdominios
- **Toggle:** Checkbox "Subdominios"
- **Efecto:** Muestra/oculta todos los nodos de tipo subdomain y sus edges

#### Filtro IPs
- **Toggle:** Checkbox "IPs"
- **Efecto:** Muestra/oculta todos los nodos de tipo IP y sus edges

#### Filtro Puertos
- **Toggle:** Checkbox "Puertos"
- **Efecto:** Muestra/oculta todos los nodos de tipo port y sus edges

#### Filtro Servicios
- **Toggle:** Checkbox "Servicios"
- **Efecto:** Muestra/oculta todos los nodos de tipo service y sus edges

#### Filtro Vulnerabilidades
- **Toggle:** Checkbox "Vulnerabilidades"
- **Efecto:** Muestra/oculta todos los nodos de tipo CVE y sus edges

**Nota:** Los filtros son acumulativos. Se pueden combinar múltiples filtros simultáneamente.

### Búsqueda

#### Campo de Búsqueda
- **Ubicación:** Parte superior del panel de grafo
- **Función:** Busca nodos por texto en su label
- **Búsqueda:** Case-insensitive, búsqueda parcial
- **Resultado:** Resalta nodos encontrados con borde amarillo grueso
- **Navegación:** Presionar Enter para ciclar entre múltiples resultados

#### Ejemplo de Uso
```
Buscar: "example"
Resultados:
  - example.com (target)
  - www.example.com (subdomain)
  - blog.example.com (subdomain)

Enter 1: Centra en example.com
Enter 2: Centra en www.example.com
Enter 3: Centra en blog.example.com
Enter 4: Vuelve a example.com
```

### Interacciones con el Grafo

#### Zoom
- **Scroll del mouse:** Zoom in/out
- **Pinch en touch:** Zoom en dispositivos táctiles
- **Límites:** Min 0.1x, Max 10x

#### Pan (Desplazamiento)
- **Click y arrastrar:** Mueve el grafo
- **Touch y arrastrar:** Desplazamiento en móviles

#### Selección de Nodos
- **Click en nodo:** Selecciona el nodo y muestra detalles
- **Efecto visual:** Borde destacado en el nodo seleccionado
- **Panel de información:** Se actualiza con datos del nodo

## Panel de Información

Cuando se selecciona un nodo, aparece un panel con información detallada según el tipo:

### Target
```
Tipo: Target
Dominio: example.com
```

### Subdomain
```
Tipo: Subdomain
Subdominio: www.example.com
IP: 93.184.216.34
```

### IP
```
Tipo: IP Address
IP: 93.184.216.34
```

### Port
```
Tipo: Port
Puerto: 443
Estado: open
```

### Service
```
Tipo: Service
Servicio: https
Producto: nginx
Versión: 1.20.1
```

### CVE
```
Tipo: Vulnerability
CVE: CVE-2023-12345
Severidad: HIGH
CVSS: 8.5
Descripción: Remote code execution vulnerability...
```

## Algoritmo de Layout

### COSE (Compound Spring Embedder)

El grafo utiliza un algoritmo force-directed que simula fuerzas físicas entre nodos.

**Parámetros configurados:**
```javascript
layout: {
  name: 'cose',
  animate: true,
  animationDuration: 500,
  idealEdgeLength: 100,
  nodeOverlap: 20,
  refresh: 20,
  fit: true,
  padding: 30,
  randomize: false,
  componentSpacing: 100,
  nodeRepulsion: 400000,
  edgeElasticity: 100,
  nestingFactor: 5,
  gravity: 80,
  numIter: 1000,
  initialTemp: 200,
  coolingFactor: 0.95,
  minTemp: 1.0
}
```

**Ventajas:**
- Distribución automática óptima de nodos
- Minimiza cruces de edges
- Agrupa nodos relacionados
- Mantiene jerarquía visual

## Estilos y Colores

### Paleta de Colores

El grafo utiliza la paleta de colores de Bootstrap 5 para consistencia visual:

- **Rojo (#dc3545):** Elementos críticos (Target, CVE CRITICAL)
- **Azul (#0d6efd):** Subdominios
- **Verde (#198754):** IPs
- **Naranja (#fd7e14):** Puertos, CVE HIGH
- **Morado (#6f42c1):** Servicios
- **Amarillo (#ffc107):** CVE MEDIUM
- **Azul claro (#17a2b8):** CVE LOW

### Estilos de Bordes (Edges)

```css
'curve-style': 'bezier',
'target-arrow-shape': 'triangle',
'arrow-scale': 1.5,
'line-color': '#cccccc',
'target-arrow-color': '#cccccc',
'width': 2
```

### Tema Claro/Oscuro

El grafo se adapta automáticamente al tema activo:
- **Tema claro:** Fondo blanco, edges grises claros
- **Tema oscuro:** Fondo oscuro, edges grises oscuros

## Casos de Uso

### 1. Análisis de Superficie de Ataque
Visualizar todos los puntos de entrada potenciales:
1. Activar todos los filtros
2. Identificar cadenas: Target → Subdomain → IP → Port → Service → CVE
3. Priorizar nodos CVE con severidad CRITICAL/HIGH

### 2. Mapeo de Infraestructura
Entender la infraestructura del objetivo:
1. Desactivar filtros de servicios y CVEs
2. Enfocarse en Target → Subdomain → IP → Port
3. Identificar patrones de hosting (IPs compartidas, CDNs)

### 3. Análisis de Vulnerabilidades
Identificar servicios vulnerables:
1. Desactivar filtros de subdominios e IPs
2. Enfocarse en Port → Service → CVE
3. Buscar CVEs por ID específico
4. Trazar ruta desde CVE hasta subdominio afectado

### 4. Reconocimiento Rápido
Obtener overview del escaneo:
1. Click en "Fit" para ver todo el grafo
2. Identificar nodos target (rojo grande)
3. Contar subdominios (círculos azules)
4. Localizar vulnerabilidades (diamantes coloreados)

## Performance

### Recomendaciones

- **Óptimo:** Hasta 200 nodos
- **Bueno:** 200-500 nodos
- **Aceptable:** 500-1000 nodos
- **Lento:** 1000+ nodos

### Optimizaciones Implementadas

1. **Lazy loading:** El grafo solo se carga al acceder a la pestaña
2. **Filtros eficientes:** Uso de clases CSS para show/hide
3. **Layout cacheado:** No se recalcula en cada interacción
4. **Throttling:** Búsqueda con debounce para evitar renders excesivos

### Tips para Grafos Grandes

- Usar filtros para reducir elementos visibles
- Buscar nodos específicos en lugar de explorar todo
- Exportar a PNG para análisis offline
- Considerar dividir el escaneo en múltiples targets

## Troubleshooting

### El grafo no se muestra
- Verificar que el escaneo esté completado
- Revisar consola del navegador para errores JavaScript
- Confirmar que endpoint `/api/scan/<scan_id>/graph` retorna 200

### Grafo muy lento
- Reducir nodos con filtros
- Cerrar otras pestañas del navegador
- Usar navegador basado en Chromium para mejor performance

### Nodos superpuestos
- Click en "Reset" para recalcular layout
- Ajustar parámetros COSE si persiste el problema

### No se exporta el PNG
- Verificar permisos de descarga en el navegador
- Intentar en modo ventana normal (no incógnito)

## Extensiones Futuras

### Planeadas
- [ ] Layout alternativo: hierarchical (árbol)
- [ ] Filtros por severidad de CVE
- [ ] Exportación a formatos adicionales (SVG, PDF)
- [ ] Modo de presentación fullscreen
- [ ] Anotaciones y marcadores personalizados
- [ ] Compartir grafo vía URL

### En Consideración
- [ ] Clustering automático de nodos similares
- [ ] Timeline de descubrimiento
- [ ] Comparación entre escaneos
- [ ] Integración con MITRE ATT&CK
- [ ] Exportación a herramientas de threat modeling

## Referencias

- [Cytoscape.js Documentation](https://js.cytoscape.org/)
- [COSE Layout Paper](https://doi.org/10.1142/S0218654307000203)
- [Bootstrap 5.3 Colors](https://getbootstrap.com/docs/5.3/customize/color/)
