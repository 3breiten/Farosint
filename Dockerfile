FROM debian:bookworm

LABEL maintainer="Mariano Breitenberger"
LABEL org.opencontainers.image.title="FAROSINT"
LABEL org.opencontainers.image.description="OSINT & Attack Surface Analysis Framework"
LABEL org.opencontainers.image.version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV GO_VERSION=1.22.5
ENV GOROOT=/usr/local/go
ENV GOPATH=/home/farosint/go

# ── Sistema base ──────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core
    wget curl git ca-certificates unzip \
    # Python
    python3 python3-pip python3-venv python3-dev \
    # Build tools (para compilar paquetes Python con extensiones C)
    build-essential libssl-dev libffi-dev \
    # Herramientas OSINT vía apt
    nmap gobuster whatweb dnsrecon \
    # Perl + libs (nikto.pl lo requiere)
    perl libnet-ssleay-perl libio-socket-ssl-perl libwhisker2-perl \
    # SNMP
    snmp snmpd \
    # SMB / enum4linux-ng
    smbclient \
    # LDAP
    ldap-utils \
    # Miscelánea
    iputils-ping net-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Usuario farosint (las rutas en el código están hardcodeadas a ~/FAROSINT) ─
RUN useradd -m -s /bin/bash farosint

# ── Go ────────────────────────────────────────────────────────────────────────
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# ── Go tools: subfinder, httpx, nuclei, amass ─────────────────────────────────
# Instalados como farosint para que queden en ~/go/bin/ (ruta que espera el engine)
USER farosint
ENV PATH="/usr/local/go/bin:/home/farosint/go/bin:${PATH}"

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1 | tail -2 \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest         2>&1 | tail -2 \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest    2>&1 | tail -2 \
    && go install github.com/owasp-amass/amass/v4/...@latest                 2>&1 | tail -2

USER root
# Amass también en /usr/local/bin (base_module lo busca ahí como primera opción)
RUN cp /home/farosint/go/bin/amass /usr/local/bin/amass 2>/dev/null || true

# ── RustScan ──────────────────────────────────────────────────────────────────
RUN wget -q "https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb" \
        -O /tmp/rustscan.deb \
    && dpkg -i /tmp/rustscan.deb || apt-get -f install -y -qq \
    && cp /usr/bin/rustscan /usr/local/bin/rustscan 2>/dev/null || true \
    && rm -f /tmp/rustscan.deb \
    ; echo "RustScan listo"

# ── Clonar dependencias externas ──────────────────────────────────────────────
RUN mkdir -p /home/farosint/tools \
    && git clone -q https://github.com/sullo/nikto.git \
        /home/farosint/tools/nikto \
    && git clone -q https://github.com/cddmp/enum4linux-ng.git \
        /home/farosint/tools/enum4linux-ng \
    && chown -R farosint:farosint /home/farosint/tools

# ── Código de la aplicación ───────────────────────────────────────────────────
COPY --chown=farosint:farosint . /home/farosint/FAROSINT/

# theHarvester viene en el repo; si por alguna razón no está, clonarlo
RUN if [ ! -f /home/farosint/FAROSINT/tools/theHarvester/theHarvester.py ]; then \
        git clone -q https://github.com/laramies/theHarvester.git \
            /home/farosint/FAROSINT/tools/theHarvester \
        && chown -R farosint:farosint /home/farosint/FAROSINT/tools/theHarvester; \
    fi

# ── Virtualenv Python + dependencias ─────────────────────────────────────────
USER farosint
RUN python3 -m venv /home/farosint/FAROSINT/farosint-env \
    && /home/farosint/FAROSINT/farosint-env/bin/pip install --upgrade pip -q \
    && /home/farosint/FAROSINT/farosint-env/bin/pip install \
        --no-cache-dir -q \
        -r /home/farosint/FAROSINT/requirements.txt

# ── Directorios runtime ───────────────────────────────────────────────────────
RUN mkdir -p \
    /home/farosint/FAROSINT/output \
    /home/farosint/FAROSINT/engine/logs \
    /home/farosint/FAROSINT/engine/cache \
    /home/farosint/nuclei-templates \
    /data

# ── Entrypoint ────────────────────────────────────────────────────────────────
USER root
COPY --chown=farosint:farosint docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Variables de entorno finales ──────────────────────────────────────────────
ENV GOROOT=/usr/local/go
ENV GOPATH=/home/farosint/go
ENV PATH="/home/farosint/FAROSINT/farosint-env/bin:/home/farosint/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin"
ENV PYTHONPATH=/home/farosint/FAROSINT
ENV FAROSINT_DOCKER=1

WORKDIR /home/farosint/FAROSINT
EXPOSE 5000

# /data → base de datos y output persistentes (montado como volumen)
VOLUME ["/data"]

USER farosint
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/home/farosint/FAROSINT/farosint-env/bin/python3", "gui/app.py"]
