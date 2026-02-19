#!/bin/bash
# FAROSINT Docker Entrypoint
# Gestiona la persistencia de datos antes de arrancar la app

set -e

DATA_DIR="/data"
DB_SOURCE="${DATA_DIR}/farosint.db"
DB_TARGET="/home/farosint/FAROSINT/gui/farosint.db"
OUTPUT_SOURCE="${DATA_DIR}/output"
OUTPUT_TARGET="/home/farosint/FAROSINT/output"
LOGS_SOURCE="${DATA_DIR}/logs"
LOGS_TARGET="/home/farosint/FAROSINT/engine/logs"
NUCLEI_SOURCE="${DATA_DIR}/nuclei-templates"
NUCLEI_TARGET="/home/farosint/nuclei-templates"

# ── Base de datos ─────────────────────────────────────────────────────────────
# Si no existe en /data, crear archivo vacío (el app inicializa el schema)
if [ ! -f "${DB_SOURCE}" ]; then
    touch "${DB_SOURCE}"
fi
# Reemplazar el db del contenedor con el persistente
ln -sf "${DB_SOURCE}" "${DB_TARGET}"

# ── Output ────────────────────────────────────────────────────────────────────
mkdir -p "${OUTPUT_SOURCE}"
rm -rf "${OUTPUT_TARGET}"
ln -sf "${OUTPUT_SOURCE}" "${OUTPUT_TARGET}"

# ── Logs ──────────────────────────────────────────────────────────────────────
mkdir -p "${LOGS_SOURCE}"
rm -rf "${LOGS_TARGET}"
ln -sf "${LOGS_SOURCE}" "${LOGS_TARGET}"

# ── Nuclei templates ──────────────────────────────────────────────────────────
mkdir -p "${NUCLEI_SOURCE}"
rm -rf "${NUCLEI_TARGET}"
ln -sf "${NUCLEI_SOURCE}" "${NUCLEI_TARGET}"

echo "FAROSINT Docker iniciando..."
echo "  Dashboard: http://localhost:5000"
echo "  Datos persistentes en: ${DATA_DIR}"
echo ""

exec "$@"
