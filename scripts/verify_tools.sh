#!/bin/bash

echo "=== Verificación de Herramientas FAROSINT ==="
echo ""

tools=(
    "nmap:Nmap"
    "amass:Amass"
    "subfinder:Subfinder"
    "httpx:Httpx"
    "nuclei:Nuclei"
    "whatweb:WhatWeb"
    "theHarvester:theHarvester"
    "masscan:Masscan"
    "go:Go"
    "node:Node.js"
    "python3:Python"
)

for tool_info in "${tools[@]}"; do
    IFS=':' read -r cmd name <<< "$tool_info"
    if command -v "$cmd" &> /dev/null; then
        version=$(${cmd} --version 2>&1 | head -n1 || ${cmd} version 2>&1 | head -n1)
        echo "✓ $name: OK"
    else
        echo "✗ $name: NO ENCONTRADO"
    fi
done

echo ""
echo "=== Verificación Completa ==="
