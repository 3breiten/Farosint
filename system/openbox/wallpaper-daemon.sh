#!/bin/bash
# Fondo de pantalla FAROSINT - event-driven via X11 RandR
# Se re-aplica EXACTAMENTE cuando cambia la resolución, sin polling
WALLPAPER="/home/farosint/Farosint_1920x1080.png"

apply_wallpaper() {
    feh --bg-fill "$WALLPAPER"
}

# Aplicar al inicio
apply_wallpaper

# Escuchar eventos de cambio de pantalla (X11 RandR events en root window)
xev -root -event structure 2>/dev/null | \
    grep --line-buffered "ConfigureNotify" | \
    while IFS= read -r _; do
        apply_wallpaper
    done
