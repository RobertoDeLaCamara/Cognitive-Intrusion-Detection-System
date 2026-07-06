# CNDS Network Sandbox

Entorno Docker aislado que simula una **red doméstica completa** para probar el sistema CNDS de extremo a extremo: captura de paquetes, detección multi-engine, Guardian auto-response (bloqueo DNS via AdGuard Home), y dashboard de visualización.

A diferencia del sandbox basado en API (`sandbox/orchestrator.py`), este entorno genera **tráfico real** en una red Docker — el detector usa Scapy para capturar paquetes exactamente como lo haría en producción.

---

## Topología

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Docker Network: homenet (172.20.0.0/24)                                │
│                                                                         │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐       ┌─────────────────────┐  │
│  │ laptop  │  │  phone  │  │ smart-tv │       │     attacker        │  │
│  │  .10    │  │  .11    │  │   .12    │       │      .66            │  │
│  │ (HTTP,  │  │ (DNS,   │  │ (UDP     │       │ (scans, floods,     │  │
│  │  SSH,   │  │  HTTPS) │  │  stream) │       │  injections, DoS)   │  │
│  │  DNS)   │  │         │  │          │       │                     │  │
│  └────┬────┘  └────┬────┘  └────┬─────┘       └──────────┬──────────┘  │
│       │             │            │                         │             │
│  ─────┼─────────────┼────────────┼─────────────────────────┼───────────  │
│       │             │            │                         │             │
│  ┌────┴─────────────┴────────────┴──────┐    ┌────────────┴──────────┐  │
│  │   AdGuard Home (DNS + enforcement)   │    │    CNDS Detector      │  │
│  │   172.20.0.2                         │    │    172.20.0.3         │  │
│  │   :53 (DNS) / :3000 (WebUI)         │    │    captures eth0      │  │
│  └──────────────────────────────────────┘    └───────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Docker Network: backend (internal, no capture)                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────────────────────────┐│
│  │ postgres │  │ cnds-api │  │ dashboard │  │  detector (también)    ││
│  │          │  │  :8000   │  │  :8501    │  │                        ││
│  └──────────┘  └──────────┘  └───────────┘  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Levantar la infraestructura + clientes legítimos

```bash
docker compose -f docker-compose.sandbox.yml up --build -d
```

Esto arranca:
- PostgreSQL (BD)
- AdGuard Home (DNS + enforcement)
- CNDS API + Detector (con Guardian habilitado)
- Dashboard Streamlit
- 3 clientes generando tráfico legítimo

### 2. Verificar que todo está corriendo

```bash
docker compose -f docker-compose.sandbox.yml ps
```

### 3. Acceder a las UIs

| Servicio | URL | Credenciales |
|----------|-----|--------------|
| **CNDS Dashboard** | http://localhost:8501 | — |
| **CNDS API** (Swagger) | http://localhost:8000/docs | — |
| **AdGuard Home** | http://localhost:3000 | admin / sandbox123 |

### 4. Lanzar el atacante

```bash
docker compose -f docker-compose.sandbox.yml --profile attack up -d attacker
```

El atacante ejecuta ciclos de 3-5 ataques aleatorios cada 30 segundos:
- SYN Scan (50+ puertos)
- ICMP Flood (100+ paquetes)
- SQL Injection (payloads HTTP reales)
- XSS (payloads HTTP)
- Path Traversal / LFI
- SYN Flood DoS
- UDP Flood
- SSH Brute Force
- DNS Enumeration
- Slow HTTP (Slowloris)

### 5. Observar la detección

```bash
# Ver alertas en tiempo real
curl -s http://localhost:8000/api/alerts?limit=10 | python -m json.tool

# Ver estadísticas
curl -s http://localhost:8000/api/stats | python -m json.tool

# Ver logs del detector
docker logs -f sandbox-detector

# Ver logs del atacante
docker logs -f sandbox-attacker
```

### 6. Verificar que Guardian bloquea al atacante

```bash
# Consultar acciones de mitigación
curl -s http://localhost:8000/api/dns-log | python -m json.tool

# Ver la lista de bloqueados en AdGuard
curl -s -u admin:sandbox123 http://localhost:3000/control/access/list | python -m json.tool
```

Deberías ver `172.20.0.66` (el atacante) en `disallowed_clients` después de que se generen alertas de severidad alta.

### 7. Parar todo

```bash
docker compose -f docker-compose.sandbox.yml --profile attack down -v
```

---

## Configuración

El archivo `.env.sandbox` contiene todos los parámetros, optimizados para demo:

| Parámetro | Valor Sandbox | Producción | Razón |
|-----------|---------------|------------|-------|
| `ENSEMBLE_THRESHOLD` | 0.40 | 0.55 | Más sensible → más alertas |
| `ICMP_FLOOD_THRESHOLD` | 20 | 50 | Dispara con menos paquetes |
| `PORT_SCAN_THRESHOLD` | 10 | 20 | Detecta scans más rápido |
| `ALERT_COOLDOWN_SECS` | 15 | 60 | Permite más alertas repetidas |
| `GUARDIAN_MIN_SEVERITY` | high | critical | Bloquea más agresivamente |
| `GUARDIAN_BLOCK_MINUTES` | 5 | 30 | Rollback rápido para iterar |
| `GUARDIAN_POLL_INTERVAL_SECS` | 5 | 15 | Reacciona más rápido |
| `IP_BLOCKLIST` | 172.20.0.66 | _(vacío)_ | Marca al atacante como crítico |

---

## Estructura de archivos

```
docker-compose.sandbox.yml     # Orquestación completa
.env.sandbox                   # Configuración del sandbox
sandbox/net/
├── Dockerfile.client          # Imagen de clientes legítimos
├── client_traffic.py          # Generador de tráfico: laptop, phone, smart-tv
├── Dockerfile.attacker        # Imagen del atacante (nmap, hping3, scapy)
├── attacker_traffic.py        # 10 tipos de ataques reales
└── adguard/
    └── conf/
        └── AdGuardHome.yaml   # Configuración pre-seed de AdGuard
```

---

## Flujo de detección esperado

1. **Clientes legítimos** generan tráfico normal (DNS, HTTP, streaming) → el detector aprende el baseline y no genera alertas (o muy pocas, con score bajo).

2. **El atacante** lanza ataques → el detector ve:
   - Port scan (10+ SYNs a puertos distintos) → regla `port_scan`
   - ICMP flood (20+ pings rápidos) → regla `icmp_flood`
   - SQL injection en payload HTTP → regla `sql_injection`
   - IP 172.20.0.66 en la blocklist → boost automático a `critical`

3. **Ensemble** combina scores de todos los engines → alerta `high` o `critical`.

4. **Guardian** detecta alerta `high+` de `172.20.0.66`:
   - Verifica que no está en whitelist ✓
   - Llama a AdGuard API → añade a `disallowed_clients`
   - Crea registro en `mitigation_actions` con `expires_at` = ahora + 5 min

5. **Auto-rollback**: pasados 5 minutos, `guardian_expiry_loop` elimina el bloqueo.

---

## Troubleshooting

**El detector no captura tráfico:**
- Verificar que la interfaz es `eth0`: `docker exec sandbox-detector ip addr`
- El detector necesita `cap_add: NET_ADMIN, NET_RAW`

**AdGuard no arranca:**
- Si ya usaste el directorio `adguard/work`, puede haber conflictos. Limpia: `rm -rf sandbox/net/adguard/work/*`

**Guardian no bloquea:**
- Verificar que `GUARDIAN_ENABLED=true` en los logs: `docker logs sandbox-detector | grep -i guardian`
- Verificar que hay alertas high/critical: `curl localhost:8000/api/alerts?severity=high`
- Verificar la conectividad detector→adguard: `docker exec sandbox-detector curl http://172.20.0.2:3000/control/access/list`

**El atacante no genera alertas:**
- Los primeros 15s el atacante espera → dale tiempo
- El detector necesita `MIN_PACKETS_FOR_ML=3` packets antes de evaluar un flow

---

## Diferencias con el sandbox de API (`sandbox/orchestrator.py`)

| Aspecto | Sandbox de API | Sandbox de Red (este) |
|---------|---------------|----------------------|
| Tráfico | Sintético vía HTTP POST a `/api/predict` | Paquetes reales capturados por Scapy |
| Feature extraction | Skip (features pre-calculadas) | Completa (flow, host, payload, JA3) |
| Guardian | No probado (no hay AdGuard) | Funcional con AdGuard real |
| Velocidad | 2-30 min | Continuo (while running) |
| Propósito | CI/demo rápida | Validación E2E realista |
