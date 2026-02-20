#!/bin/bash
###############################################################################
# FAROSINT ISO Builder
# Genera un ISO instalador basado en Debian 12 con branding FAROSINT
#
# Uso: sudo bash build-iso.sh
# Resultado: FAROSINT-v1.0-installer.iso (~500MB)
###############################################################################

set -e

WORK_DIR="/tmp/farosint-iso-build"
FAROSINT_DIR="/home/farosint/FAROSINT"
ISO_ASSETS="${FAROSINT_DIR}/iso-build/farosint-iso"
OUTPUT_ISO="${FAROSINT_DIR}/iso-build/FAROSINT-v1.0-installer.iso"

# Debian 12 netinstall (mínima, ~600MB)
DEBIAN_ISO_URL="https://cdimage.debian.org/cdimage/archive/latest-oldstable/amd64/iso-cd/debian-12.13.0-amd64-netinst.iso"
DEBIAN_ISO="/tmp/debian-12-netinst.amd64.iso"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${CYAN}► $1${NC}"; }
ok()   { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
err()  { echo -e "${RED}✗ $1${NC}"; exit 1; }

# Verificar root
[ "$EUID" -ne 0 ] && err "Ejecutar como root: sudo bash build-iso.sh"

# Verificar herramientas
for tool in xorriso wget; do
    command -v $tool &>/dev/null || err "$tool no instalado. Correr: apt install -y xorriso wget"
done

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     FAROSINT ISO Builder v1.0            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Descargar ISO base de Debian ───────────────────────────────────────────
log "Paso 1/5: Descargando Debian 12 netinstall ISO..."
if [ ! -f "${DEBIAN_ISO}" ]; then
    wget -q --show-progress "${DEBIAN_ISO_URL}" -O "${DEBIAN_ISO}" || err "Error descargando ISO"
    ok "ISO descargado ($(du -sh ${DEBIAN_ISO} | cut -f1))"
else
    ok "ISO ya descargado, reutilizando"
fi

# ── 2. Extraer ISO ─────────────────────────────────────────────────────────────
log "Paso 2/5: Extrayendo ISO..."
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/iso"

xorriso -osirrox on \
    -indev "${DEBIAN_ISO}" \
    -extract / "${WORK_DIR}/iso" \
    2>/dev/null

chmod -R u+w "${WORK_DIR}/iso"
ok "ISO extraído en ${WORK_DIR}/iso"

# ── 3. Inyectar preseed y branding ────────────────────────────────────────────
log "Paso 3/5: Aplicando branding FAROSINT..."

# Preseed
mkdir -p "${WORK_DIR}/iso/preseed"
cp "${ISO_ASSETS}/preseed/farosint.cfg" "${WORK_DIR}/iso/preseed/"
ok "Preseed copiado"

# GRUB config
cp "${ISO_ASSETS}/grub/grub.cfg" "${WORK_DIR}/iso/boot/grub/grub.cfg"
ok "GRUB config aplicado"

# Logo FAROSINT como splash (si existe)
LOGO="${FAROSINT_DIR}/gui/static/images/logo.png"
if [ -f "${LOGO}" ]; then
    cp "${LOGO}" "${WORK_DIR}/iso/boot/grub/splash.png"
    # Agregar la línea del splash al grub.cfg
    sed -i '3a background_image /boot/grub/splash.png' "${WORK_DIR}/iso/boot/grub/grub.cfg"
    ok "Logo FAROSINT aplicado como splash"
else
    warn "Logo no encontrado en ${LOGO}, se omite splash"
fi

# Archivo de identificación FAROSINT en el ISO
cat > "${WORK_DIR}/iso/.farosint" << EOF
FAROSINT OSINT & Attack Surface Analysis Framework
Version: 1.0.0
Author: Mariano Breitenberger
Build date: $(date '+%Y-%m-%d')
Based on: Debian 12 (bookworm)
Repo: https://github.com/3breiten/Farosint
EOF
ok "Firma FAROSINT embebida"

# ── 4. Regenerar MD5 checksums ─────────────────────────────────────────────────
log "Paso 4/5: Regenerando checksums..."
cd "${WORK_DIR}/iso"
find . -type f ! -name "md5sum.txt" ! -path "./isolinux/*" \
    -exec md5sum {} \; 2>/dev/null > md5sum.txt || true
ok "Checksums actualizados"

# ── 5. Empacar nuevo ISO ───────────────────────────────────────────────────────
log "Paso 5/5: Generando FAROSINT-v1.0-installer.iso..."

# Extraer MBR del ISO original para hacerlo booteable
MBR_FILE="/tmp/farosint-mbr.img"
dd if="${DEBIAN_ISO}" bs=1 count=432 of="${MBR_FILE}" 2>/dev/null

xorriso -as mkisofs \
    -r \
    -J \
    -joliet-long \
    -l \
    -iso-level 3 \
    -partition_offset 16 \
    --grub2-mbr "${MBR_FILE}" \
    --protective-msdos-label \
    -append_partition 2 0xEF "${WORK_DIR}/iso/boot/grub/efi.img" \
    -appended_part_as_gpt \
    -c isolinux/boot.cat \
    -b isolinux/isolinux.bin \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    -o "${OUTPUT_ISO}" \
    "${WORK_DIR}/iso"

ok "ISO generado: ${OUTPUT_ISO}"
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  FAROSINT-v1.0-installer.iso listo!${NC}"
echo -e "${GREEN}  Tamaño: $(du -sh ${OUTPUT_ISO} | cut -f1)${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo "Para probar con QEMU:"
echo "  qemu-system-x86_64 -cdrom ${OUTPUT_ISO} -m 2048 -boot d"
echo ""
echo "Para grabar en USB:"
echo "  sudo dd if=${OUTPUT_ISO} of=/dev/sdX bs=4M status=progress"
echo ""

# Limpiar archivos temporales
rm -rf "${WORK_DIR}" "${MBR_FILE}"
