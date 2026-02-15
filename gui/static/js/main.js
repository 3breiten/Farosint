/**
 * FAROSINT Dashboard - Main JavaScript
 * Funcionalidad general del dashboard
 */

// Inicialización cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    console.log('FAROSINT Dashboard cargado');
    
    // Inicializar tooltips de Bootstrap
    initTooltips();
    
    // Configurar notificaciones
    setupNotifications();
    
    // Auto-refresh de badges en tiempo real
    if (typeof io !== 'undefined') {
        initWebSocket();
    }
});

/**
 * Inicializar tooltips de Bootstrap
 */
function initTooltips() {
    const tooltipTriggerList = [].slice.call(
        document.querySelectorAll('[data-bs-toggle="tooltip"]')
    );
    
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Sistema de notificaciones
 */
function setupNotifications() {
    // Verificar si el navegador soporta notificaciones
    if ('Notification' in window) {
        // Pedir permiso si no está concedido
        if (Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }
}

/**
 * Mostrar notificación toast
 */
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    
    if (!toastContainer) {
        // Crear contenedor si no existe
        const container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(container);
    }
    
    const toastId = 'toast-' + Date.now();
    const bgClass = {
        'success': 'bg-success',
        'error': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-info';
    
    const toastHTML = `
        <div id="${toastId}" class="toast ${bgClass} text-white" role="alert">
            <div class="toast-header ${bgClass} text-white">
                <strong class="me-auto">FAROSINT</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    const container = document.getElementById('toastContainer');
    container.insertAdjacentHTML('beforeend', toastHTML);
    
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { delay: 5000 });
    toast.show();
    
    // Eliminar del DOM después de ocultarse
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

/**
 * Mostrar notificación del navegador
 */
function showBrowserNotification(title, message) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: message,
            icon: '/static/img/logo.svg',
            badge: '/static/img/logo.svg'
        });
    }
}

/**
 * Inicializar WebSocket para actualizaciones en tiempo real
 */
function initWebSocket() {
    const socket = io();
    
    socket.on('connect', function() {
        console.log('WebSocket conectado');
    });
    
    socket.on('disconnect', function() {
        console.log('WebSocket desconectado');
    });
    
    socket.on('scan_started', function(data) {
        showToast(`Escaneo iniciado: ${data.target}`, 'info');
        showBrowserNotification('Escaneo Iniciado', `Objetivo: ${data.target}`);
    });
    
    socket.on('scan_completed', function(data) {
        showToast(`Escaneo completado: ${data.scan_id}`, 'success');
        showBrowserNotification('Escaneo Completado', 
            `Subdominios: ${data.results.subdomains}, Vulnerabilidades: ${data.results.vulnerabilities}`);
        
        // Recargar página si estamos en el dashboard
        if (window.location.pathname === '/') {
            setTimeout(() => location.reload(), 2000);
        }
    });
    
    socket.on('scan_failed', function(data) {
        showToast(`Escaneo fallido: ${data.error}`, 'error');
        showBrowserNotification('Escaneo Fallido', data.error);
    });
}

/**
 * Formatear fecha relativa (ej: "hace 2 horas")
 */
function timeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    const intervals = {
        año: 31536000,
        mes: 2592000,
        semana: 604800,
        día: 86400,
        hora: 3600,
        minuto: 60,
        segundo: 1
    };
    
    for (const [name, value] of Object.entries(intervals)) {
        const interval = Math.floor(seconds / value);
        if (interval >= 1) {
            return `hace ${interval} ${name}${interval > 1 ? 's' : ''}`;
        }
    }
    
    return 'justo ahora';
}

/**
 * Copiar texto al portapapeles
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showToast('Copiado al portapapeles', 'success');
    }).catch(function(err) {
        console.error('Error al copiar:', err);
        showToast('Error al copiar', 'error');
    });
}

/**
 * Validar dominio
 */
function isValidDomain(domain) {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
    return domainRegex.test(domain);
}

/**
 * Formatear bytes a tamaño legible
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Exportar tabla a CSV
 */
function exportTableToCSV(tableId, filename = 'export.csv') {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    let csv = [];
    const rows = table.querySelectorAll('tr');
    
    for (let row of rows) {
        let rowData = [];
        const cols = row.querySelectorAll('td, th');
        
        for (let col of cols) {
            rowData.push('"' + col.innerText.replace(/"/g, '""') + '"');
        }
        
        csv.push(rowData.join(','));
    }
    
    // Crear blob y descargar
    const csvContent = csv.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}

// Exponer funciones globalmente
window.FAROSINT = {
    showToast,
    showBrowserNotification,
    timeAgo,
    copyToClipboard,
    isValidDomain,
    formatBytes,
    exportTableToCSV
};
