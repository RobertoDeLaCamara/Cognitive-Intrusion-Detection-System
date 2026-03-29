# CNDS — Modelos de ML/AI: Entrenamiento y Reentrenamiento

Este documento cubre en detalle los tres modelos de machine learning del sistema (Random Forest, Isolation Forest, LSTM Autoencoder), su ingeniería de features, los parámetros exactos de configuración, los procedimientos de entrenamiento inicial y reentrenamiento, la calibración del ensemble, el sistema de pesos adaptativos y la integración con MLflow.

---

## Índice

1. [Visión general del pipeline de ML](#1-visión-general-del-pipeline-de-ml)
2. [Ingeniería de Features](#2-ingeniería-de-features)
   - 2.1 [76 Flow Features (CICFlowMeter)](#21-76-flow-features-cicflowmeter)
   - 2.2 [18 Host Features](#22-18-host-features)
   - 2.3 [10 Payload Features](#23-10-payload-features)
3. [Modelo 1: Random Forest (Supervisado)](#3-modelo-1-random-forest-supervisado)
4. [Modelo 2: Isolation Forest (No Supervisado)](#4-modelo-2-isolation-forest-no-supervisado)
5. [Modelo 3: LSTM Autoencoder (Temporal)](#5-modelo-3-lstm-autoencoder-temporal)
6. [Rules Engine (Heurístico)](#6-rules-engine-heurístico)
7. [Ensemble Scorer: Fusión y Calibración](#7-ensemble-scorer-fusión-y-calibración)
8. [Pesos Adaptativos (Feedback Loop)](#8-pesos-adaptativos-feedback-loop)
9. [Integración con MLflow](#9-integración-con-mlflow)
10. [Procedimientos de Entrenamiento](#10-procedimientos-de-entrenamiento)
11. [Procedimientos de Reentrenamiento](#11-procedimientos-de-reentrenamiento)
12. [Evaluación de Modelos](#12-evaluación-de-modelos)
13. [Referencia de Hiperparámetros](#13-referencia-de-hiperparámetros)

---

## 1. Visión general del pipeline de ML

```
Paquete de red (Scapy)
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│               Feature Extraction (paralela)                 │
│                                                             │
│  FlowExtractor → 76 flow features (por flujo 5-tupla)      │
│  HostExtractor → 18 host features (por IP fuente)          │
│  PayloadAnalyzer → 10 payload features (por flujo)         │
│  JA3 Fingerprinter → MD5 hash TLS ClientHello              │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│               Inference (4 motores en paralelo)             │
│                                                             │
│  RF  ──── 76 flow features ──────→ (attack_type, conf)     │
│  IF  ──── 18 host features ──────→ anomaly_score [0,1]     │
│  LSTM ─── seq de 20 × 18 feat. ──→ reconstruction_error    │
│  Rules ── flow + host + payload ─→ (1.0 si regla dispara)  │
└──────────────┬──────────────────────────────────────────────┘
               │ EngineScores
               ▼
┌─────────────────────────────────────────────────────────────┐
│               EnsembleScorer                                │
│                                                             │
│  weighted_avg(w_rf×s_rf, w_if×s_if, w_lstm×s_lstm,        │
│               w_rules×s_rules)                             │
│  → temperature scaling (Platt)                             │
│  → umbral ENSEMBLE_THRESHOLD (0.55)                        │
│  → severidad (low/medium/high/critical)                    │
└─────────────────────────────────────────────────────────────┘
```

Los tres modelos ML operan sobre **representaciones de features distintas** y detectan **tipos de amenaza complementarios**:

| Modelo | Input | Detecta | Requisito |
|---|---|---|---|
| Random Forest | 76 flow features | Ataques conocidos con nombre | Dataset etiquetado (CIC-IDS2017) |
| Isolation Forest | 18 host features | Anomalías volumétricas/comportamentales | Tráfico normal de referencia |
| LSTM Autoencoder | Secuencias temporales 20×18 | Cambios lentos / beaconing | Tráfico normal de al menos 2h |

---

## 2. Ingeniería de Features

### 2.1 76 Flow Features (CICFlowMeter)

**Archivo:** `src/features/flow_extractor.py`

Los features de flujo replican exactamente el esquema del dataset **CIC-IDS2017** del Canadian Institute for Cybersecurity, lo que permite entrenar el RF directamente sobre datos públicos sin transformación.

Cada flujo se identifica por la 5-tupla `(src_ip, dst_ip, src_port, dst_port, protocol)`. El primer paquete determina la dirección "forward" (cliente→servidor); el resto son "backward".

**Lista completa en orden de índice:**

```python
FLOW_FEATURE_NAMES = [
    # ── Duración y conteos totales ────────────────────────────────────
    "flow_duration",          # Duración del flujo en segundos
    "tot_fwd_pkts",           # Paquetes en dirección forward
    "tot_bwd_pkts",           # Paquetes en dirección backward
    "totlen_fwd_pkts",        # Bytes totales forward
    "totlen_bwd_pkts",        # Bytes totales backward

    # ── Estadísticas de longitud de paquete (forward) ─────────────────
    "fwd_pkt_len_max",        # Max longitud forward
    "fwd_pkt_len_min",        # Min longitud forward
    "fwd_pkt_len_mean",       # Media longitud forward
    "fwd_pkt_len_std",        # Desviación estándar forward

    # ── Estadísticas de longitud de paquete (backward) ────────────────
    "bwd_pkt_len_max",
    "bwd_pkt_len_min",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_std",

    # ── Tasas de flujo ────────────────────────────────────────────────
    "flow_byts_s",            # Bytes/segundo del flujo completo
    "flow_pkts_s",            # Paquetes/segundo

    # ── Inter-arrival times (IAT) a nivel de flujo ────────────────────
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",

    # ── IAT dirección forward ─────────────────────────────────────────
    "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",

    # ── IAT dirección backward ────────────────────────────────────────
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",

    # ── Flags TCP por dirección ───────────────────────────────────────
    "fwd_psh_flags", "bwd_psh_flags",
    "fwd_urg_flags", "bwd_urg_flags",

    # ── Longitudes de cabecera ────────────────────────────────────────
    "fwd_header_len", "bwd_header_len",

    # ── Tasas de paquete por dirección ────────────────────────────────
    "fwd_pkts_s", "bwd_pkts_s",

    # ── Estadísticas de longitud global ───────────────────────────────
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",

    # ── Contadores de flags TCP ───────────────────────────────────────
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "cwr_flag_count", "ece_flag_cnt",

    # ── Ratios y promedios ────────────────────────────────────────────
    "down_up_ratio",          # n_bwd / max(n_fwd, 1)
    "pkt_size_avg",           # Tamaño promedio de paquete

    # ── Segmentos promedio ────────────────────────────────────────────
    "fwd_seg_size_avg",       # Media de tamaño de segmento forward
    "bwd_seg_size_avg",

    # ── Bulk transfer ─────────────────────────────────────────────────
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
    "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",

    # ── Subflows ─────────────────────────────────────────────────────
    "subflow_fwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_pkts", "subflow_bwd_byts",

    # ── Ventanas iniciales TCP ────────────────────────────────────────
    "init_fwd_win_byts",      # Tamaño ventana TCP del primer paquete forward
    "init_bwd_win_byts",      # Tamaño ventana TCP del primer paquete backward

    # ── Paquetes con datos reales ─────────────────────────────────────
    "fwd_act_data_pkts",      # Paquetes forward con payload > 0
    "fwd_seg_size_min",       # Tamaño mínimo de segmento forward

    # ── Períodos activos/inactivos ────────────────────────────────────
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean",   "idle_std",   "idle_max",   "idle_min",
]
```

**Parámetros de extracción relevantes:**

| Variable | Default | Descripción |
|---|---|---|
| `FLOW_TIMEOUT` | 120s | Tiempo sin paquetes para flush del flujo |
| `ACTIVE_IDLE_THRESH` | 1.0s | Gap de tiempo que divide períodos activo/inactivo |
| `MAX_ACTIVE_FLOWS` | 50,000 | Techo de flujos concurrentes (LRU eviction) |
| `MIN_PACKETS_FOR_ML` | 10 | Paquetes mínimos antes de enviar a los modelos ML |
| `MAX_PAYLOAD_SAMPLES` | 50 | Samples de payload guardados por flujo |
| `PAYLOAD_SAMPLE_BYTES` | 4,096 | Bytes por sample de payload |

**Invariante:** La función `to_feature_vector()` valida que el vector resultante tenga exactamente 76 elementos; si no, retorna `None` y el flujo no se envía a los motores.

### Extensión a 86 features (con payload)

Al ejecutar el script de reentrenamiento con payload, se concatenan los 10 `PAYLOAD_FEATURE_NAMES` al final del vector de 76, produciendo un vector de 86 features. El motor supervisado detecta automáticamente el tamaño al cargar el modelo:

```python
n = getattr(self._model, "n_features_in_", 76)
self._expects_payload = (n == len(EXTENDED_FEATURE_NAMES))  # 76 + 10 = 86
```

---

### 2.2 18 Host Features

**Archivo:** `src/features/host_extractor.py`

Los host features agregan el comportamiento de una IP fuente a lo largo de una ventana deslizante de los últimos `HOST_WINDOW_SIZE` (default: 100) paquetes. Son la entrada para Isolation Forest y LSTM Autoencoder.

```python
HOST_FEATURE_NAMES = [
    # ── Estadísticos (6) ──────────────────────────────────────────────
    "packets_per_sec",         # 0: paquetes/segundo en la ventana
    "bytes_per_sec",           # 1: bytes/segundo
    "avg_packet_size",         # 2: tamaño medio de paquete
    "packet_size_var",         # 3: varianza del tamaño de paquete
    "total_packets",           # 4: total de paquetes en la ventana
    "total_bytes",             # 5: total de bytes en la ventana

    # ── Temporales (4) ───────────────────────────────────────────────
    "iat_mean",                # 6: media de tiempos entre llegadas
    "iat_std",                 # 7: desviación estándar de IAT
    "burst_rate",              # 8: paquetes en últimos 5s / 5
    "session_duration",        # 9: tiempo desde primer paquete

    # ── Protocolo (3) ────────────────────────────────────────────────
    "tcp_ratio",               # 10: fracción de paquetes TCP
    "udp_ratio",               # 11: fracción de paquetes UDP
    "icmp_ratio",              # 12: fracción de paquetes ICMP

    # ── Puertos (2) ──────────────────────────────────────────────────
    "unique_ports",            # 13: número de puertos destino distintos
    "uncommon_port_ratio",     # 14: puertos > 1024 / total

    # ── Payload (3) ──────────────────────────────────────────────────
    "avg_payload_entropy",     # 15: entropía media de payload (bytes)
    "avg_payload_size",        # 16: tamaño medio de payload
    "payload_size_var",        # 17: varianza del tamaño de payload
]
```

**Detalles de implementación clave:**

- **`burst_rate`** (índice 8): cuenta paquetes en los últimos 5 segundos y divide por 5. Muy sensible a ráfagas como floods.
- **`unique_ports`** (índice 13): puertos destino distintos en la ventana. Un port scan hace que este valor se dispare.
- **`avg_payload_entropy`** (índice 15): entropía de Shannon en bits por byte. Tráfico cifrado/comprimido tiene entropía ~7.5-8.0; texto plano ~4.0-6.0.
- **LRU eviction**: cuando se alcanza `MAX_TRACKED_IPS` (5,000), se expulsa la IP cuya `HostHistory` tiene menos paquetes. El LSTM también aplica esta política, eliminando el buffer del IP víctima.

**`COMMON_PORTS`** usados para calcular `uncommon_port_ratio`:
```python
COMMON_PORTS = {80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 8080, 8443, 21, 20, 3306, 5432}
```

---

### 2.3 10 Payload Features

**Archivo:** `src/features/payload_analyzer.py`

Extraídos de los bytes crudos del payload forward del flujo. Se pasan al motor supervisado (si fue entrenado con 86 features) y al Rules Engine.

**Índices 0–5: flags binarios de patrones**

| Índice | Nombre | Patrón regex |
|---|---|---|
| 0 | `has_sqli` | `union select`, `drop table`, `' OR '1'='1`, etc. |
| 1 | `has_xss` | `<script`, `javascript:`, `onerror=`, `alert(`, etc. |
| 2 | `has_cmdi` | `; ls`, `&& curl`, `\| bash`, backticks, `$(...)` |
| 3 | `has_traversal` | `../`, `..\`, `%2e%2e%2f`, `%252e%252e` |
| 4 | `has_log4j` | `${jndi:`, `${env:`, `${sys:`, `${java:` |
| 5 | `has_shellshock` | `() { ...; }` (CVE-2014-6271) |

**Índices 6–9: features numéricos**

| Índice | Nombre | Descripción |
|---|---|---|
| 6 | `pattern_match_count` | Número de tipos distintos de patrones que hicieron match |
| 7 | `max_payload_entropy` | Entropía máxima entre todos los payload samples del flujo |
| 8 | `mean_payload_length` | Longitud media de los payloads en el flujo |
| 9 | `suspicious_char_ratio` | Ratio de caracteres sospechosos (null bytes, control chars) |

**Protección anti-ReDoS:**
```python
def _match_with_timeout(pattern, data, timeout=1.0):
    """Ejecuta regex con timeout via threading para evitar bloqueo del pipeline."""
    result = [False]
    def _run():
        result[0] = bool(pattern.search(data))
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]
```

Cada patrón se pre-filtra con una regex barata antes de ejecutar el patrón completo para evitar overhead en tráfico benigno de alto volumen.

---

## 3. Modelo 1: Random Forest (Supervisado)

**Archivo:** `src/engines/supervised.py`
**Modelo:** `models/rf_model.joblib` (scikit-learn `Pipeline`)

### Arquitectura del modelo

El joblib contiene un `sklearn.pipeline.Pipeline` con dos etapas:

```
Pipeline
├── ("scaler") → StandardScaler  — normalización z-score de los 76/86 features
└── ("rf")     → RandomForestClassifier — clasificador principal
```

La inclusión del scaler en el Pipeline garantiza que en inferencia los features se normalizan con los parámetros estadísticos del conjunto de entrenamiento, no con los del tráfico en tiempo real.

### Dataset de entrenamiento: CIC-IDS2017

El Random Forest se entrena sobre el **CIC-IDS2017** dataset:

| Característica | Valor |
|---|---|
| Fuente | Canadian Institute for Cybersecurity |
| Duración captura | 5 días (lunes–viernes) |
| Volumen | ~2.8 millones de flujos etiquetados |
| Features | 78 columnas (76 features + Label + Flow ID) |
| Formato | CSV generado por CICFlowMeter |
| Disponibilidad | Descarga pública en cicresearch.ca |

**Clases en el dataset:**

| Etiqueta | Tipo | Día |
|---|---|---|
| BENIGN | Tráfico normal | Todos |
| DoS Hulk | HTTP flood tool Hulk | Miércoles |
| DoS GoldenEye | HTTP DoS | Miércoles |
| DoS Slowloris | Slow HTTP headers | Miércoles |
| DoS Slowhttptest | Slow HTTP body | Miércoles |
| PortScan | Nmap TCP scan | Viernes |
| FTP-Patator | Brute force FTP | Martes |
| SSH-Patator | Brute force SSH | Martes |
| Bot | Botnet C2 | Jueves |
| Infiltration | Infiltración de red | Jueves |
| Web Attack – Brute Force | Login brute force | Miércoles |
| Web Attack – XSS | Cross-site scripting | Miércoles |
| Web Attack – SQL Injection | SQLi | Miércoles |
| Heartbleed | CVE-2014-0160 | Viernes |

**Nota sobre desbalanceo:** El dataset CIC-IDS2017 es **altamente desbalanceado** — BENIGN representa ~80% de las muestras. Random Forest maneja esto razonablemente con `class_weight='balanced'`, aunque el script de reentrenamiento usa `stratify=y` en el split.

### Hiperparámetros de entrenamiento

```python
# src/scripts/retrain_with_payload.py
RandomForestClassifier(
    n_estimators  = 100,    # número de árboles (configurable con --n-estimators)
    random_state  = 42,     # reproducibilidad
    n_jobs        = -1,     # usar todos los cores disponibles
)

train_test_split(
    X, y,
    test_size    = 0.2,    # 80% train, 20% test
    random_state = 42,
    stratify     = y,      # mantener proporciones de clases
)
```

**Notas:**
- `n_estimators=100` es conservador; para producción se recomienda 200–500 con `min_samples_leaf=2`.
- No se configura `max_depth` ni `max_features` — se usan los defaults de sklearn (`max_features='sqrt'`).
- El script reporta `classification_report` completo con precision/recall/F1 por clase al finalizar.

### Inferencia

```python
def predict(self, flow_features, payload_features=None):
    # Construir vector
    vec = flow_features  # shape (76,)
    if self._expects_payload and payload_features is not None:
        vec = np.concatenate([flow_features, payload_features])  # shape (86,)

    vec = vec.reshape(1, -1)
    label = self._model.predict(vec)[0]       # clase predicha
    proba = self._model.predict_proba(vec)[0]  # probabilidades por clase
    confidence = float(proba.max())            # confianza = prob de la clase ganadora
    return str(label), confidence
```

**Conversión a anomaly_score para el ensemble:**
- Si `label == "BENIGN"` → `score = 0.0`
- Si `label != "BENIGN"` → `score = confidence` (la probabilidad de la clase de ataque)

### Carga y degradación

```python
def _load(self):
    # 1. Intentar desde MLflow registry (si MLFLOW_TRACKING_URI configurado)
    model = mlflow_registry.load_latest("supervised")
    if model is not None:
        self._model = model
        return

    # 2. Fallback a archivo local
    if os.path.exists(self._model_path):
        self._model = joblib.load(self._model_path)
        return

    # 3. Motor deshabilitado — is_available = False
    logger.warning("RF model not found — supervised engine disabled")
```

---

## 4. Modelo 2: Isolation Forest (No Supervisado)

**Archivos:** `src/engines/isolation_forest.py`
**Modelos:** `models/isolation_forest.joblib` + `models/if_scaler.joblib`

### Fundamento teórico

Isolation Forest detecta anomalías mediante la lógica de que los **puntos anómalos son más fáciles de aislar** que los normales. Construye árboles de aislamiento aleatorios y mide cuántos splits se necesitan para aislar cada punto. Los puntos que requieren pocos splits tienen `decision_function` muy negativo → anomalía.

### Dataset de entrenamiento

A diferencia del RF, el IF **no requiere etiquetas**. Se entrena únicamente con tráfico normal (baseline):

```
Requisito mínimo:
  - 30–60 minutos de tráfico representativo de la red
  - Capturado durante horario laboral normal (no durante incidentes)
  - Suficiente diversidad: HTTP, HTTPS, DNS, NTP, tráfico de backups, etc.
  - Las IPs que se quieren monitorear deben aparecer en el baseline
```

**¿Qué va en el baseline?**

| Incluir | Excluir |
|---|---|
| Navegación web normal | Escaneos de vulnerabilidades |
| Transferencias de archivos habituales | Backups inusualmente grandes |
| Tráfico DNS regular | Pruebas de carga |
| Conexiones a servicios cloud conocidos | Tráfico de staging/CI que no aplica a producción |

### Normalización: `if_scaler.joblib`

El IF usa los 18 host features en su escala original (paquetes/sec, bytes/sec, etc.), que tienen magnitudes muy dispares. El `StandardScaler` los normaliza a media=0, std=1 antes del IF:

```python
if self._scaler is not None:
    vec = self._scaler.transform(vec)  # z-score: (x - μ) / σ
```

El scaler **debe entrenarse con el mismo dataset** que el IF. Si se entrena un nuevo IF, debe entrenarse también un nuevo scaler con los mismos datos.

### Normalización del score: Sigmoid con steepness=5

```python
raw = float(self._model.decision_function(vec)[0])
# raw > 0 → normal; raw < 0 → anomalía
score = 1.0 / (1.0 + np.exp(5.0 * raw))
```

Este mapeo tiene una propiedad importante: la **pendiente máxima** (mayor sensibilidad) ocurre en `raw = 0`, que es exactamente la frontera de decisión del IF. Valores de `raw = ±0.5` ya producen scores cercanos a 0 o 1.

**Visualización del mapeo:**

| raw (decision_function) | score (anomalía) |
|---|---|
| -1.0 | ~0.99 |
| -0.5 | ~0.92 |
| -0.2 | ~0.73 |
|  0.0 | 0.50 |
| +0.2 | ~0.27 |
| +0.5 | ~0.08 |
| +1.0 | ~0.01 |

### Parámetro `contamination`

El parámetro `contamination` del `IsolationForest` define qué fracción del dataset de entrenamiento se asume anómala. Para un baseline puro de tráfico normal, se recomienda `contamination=0.01` (1%). Valores más altos hacen el modelo más agresivo.

---

## 5. Modelo 3: LSTM Autoencoder (Temporal)

**Archivo:** `src/engines/lstm_autoencoder.py`
**Modelos:** `models/lstm_autoencoder.pt` (PyTorch) + `models/lstm_config.json`

### Arquitectura

El modelo es un autoencoder secuencia-a-secuencia basado en LSTM:

```
Input: (batch=1, seq_len=20, n_features=18)
         │
         ▼
┌─────────────────────────────────┐
│ Encoder                         │
│  LSTM(input=18, hidden=64,      │
│       num_layers=2,             │
│       dropout=0.2)              │
│  → hidden state (latent_dim=32) │
└──────────────┬──────────────────┘
               │ latent representation
               ▼
┌─────────────────────────────────┐
│ Decoder                         │
│  LSTM(input=32, hidden=64,      │
│       num_layers=2,             │
│       dropout=0.2)              │
│  → Linear(64 → 18)             │
│  → Output: (1, 20, 18)         │
└─────────────────────────────────┘
```

**Parámetros exactos del modelo en producción** (de `models/lstm_config.json`):

```json
{
  "sequence_length": 20,
  "hidden_dim":      64,
  "latent_dim":      32,
  "num_layers":      2,
  "dropout":         0.2,
  "n_features":      18,
  "threshold":       1.1036977231502532,
  "saved_at":        "2026-02-04T19:58:48.383248"
}
```

### Buffers por IP

El LSTM no procesa paquetes individuales; mantiene una **cola FIFO por IP fuente**:

```python
self._buffers: dict[str, deque] = defaultdict(
    lambda: deque(maxlen=self._seq_len)  # maxlen=20
)
```

- En cada paquete de la IP `X`, se añade su vector de 18 host features al deque.
- El deque tiene `maxlen=20` → los features más antiguos se descartan automáticamente.
- Cuando el deque está **lleno** (exactamente 20 vectores), se ejecuta el autoencoder.

**Cold-start:** Los primeros 19 paquetes de cualquier IP nueva no producen score LSTM. Durante ese período, el peso del LSTM se redistribuye a los otros motores.

**Evicción LRU:** Cuando `len(self._buffers) >= MAX_TRACKED_IPS`, el IP con el buffer más corto (menos datos) es expulsado:

```python
victim = min(self._buffers, key=lambda k: len(self._buffers[k]))
del self._buffers[victim]
```

### Inferencia y scoring

```python
def anomaly_score(self, ip: str) -> float:
    buf = self._buffers.get(ip)
    if buf is None or len(buf) < self._seq_len:
        return 0.0  # cold-start

    seq = np.array(list(buf), dtype=np.float32)  # shape (20, 18)
    x = torch.tensor(seq).unsqueeze(0)            # shape (1, 20, 18)

    with torch.no_grad():
        reconstructed = self._model(x)

    # Error de reconstrucción = MSE entre input y output
    error = float(torch.mean((x - reconstructed) ** 2).item())

    # Normalizar con threshold (1.104 en producción)
    score = min(error / max(self._threshold, 1e-9), 1.0)
    return float(score)
```

**Threshold de reconstrucción:** El `threshold` en `lstm_config.json` (1.1037) es el **MSE máximo observado en el conjunto de validación de tráfico normal**. Es el punto de normalización: un error igual al threshold produce score=1.0. Errores menores producen scores en (0, 1).

### Dataset de entrenamiento

```
Requisito mínimo: 2 horas de tráfico normal
Recomendado:      8+ horas cubriendo variaciones diurnas/nocturnas
Formato:          Secuencias de 18 host features por IP, ordenadas por tiempo
```

El entrenamiento optimiza la pérdida MSE entre input y reconstrucción:
```
Loss = MSE(x, decoder(encoder(x)))
```

El modelo converge cuando puede reproducir fielmente las secuencias normales. El `threshold` debe fijarse como el **percentil 95–99 del error de reconstrucción en validación** para calibrar la sensibilidad.

---

## 6. Rules Engine (Heurístico)

**Archivo:** `src/engines/rules.py`

El Rules Engine no tiene parámetros aprendidos pero sí **umbrales configurables** que actúan como hiperparámetros operacionales:

| Regla | Condición | Umbral configurable |
|---|---|---|
| `icmp_flood` | `n_fwd > ICMP_FLOOD_THRESHOLD` (proto=ICMP) | `ICMP_FLOOD_THRESHOLD=50` |
| `syn_scan` | `syn_flag_cnt > PORT_SCAN_THRESHOLD AND tot_fwd_pkts < 5` | `PORT_SCAN_THRESHOLD=20` |
| `large_payload` | `max(fwd_lengths) > LARGE_PAYLOAD_BYTES` | `LARGE_PAYLOAD_BYTES=10000` |
| `payload:*` | Cualquier match de los 6 patrones de payload | — (regex fijos) |
| `asymmetric_upload` | `sum(fwd_bytes) / max(sum(bwd_bytes),1) > 50` | Hardcoded ratio=50 |
| `malicious_ja3` | `ja3_hash in malicious_set` | Lista en `MALICIOUS_JA3_FILE` |

**Nota:** Los valores default son **más conservadores** de lo que parecen. Por ejemplo, `ICMP_FLOOD_THRESHOLD=50` significa 50 paquetes en el flujo acumulado, no 50/segundo. Para redes con alto tráfico ICMP legítimo (monitoreo Nagios, etc.), conviene subirlo a 200–500.

---

## 7. Ensemble Scorer: Fusión y Calibración

**Archivo:** `src/ensemble/scorer.py`

### Pesos base

```python
_BASE_WEIGHTS = {
    "supervised":       WEIGHT_SUPERVISED,    # 0.40
    "isolation_forest": WEIGHT_IFOREST,       # 0.30
    "lstm":             WEIGHT_LSTM,          # 0.20
    "rules":            WEIGHT_RULES,         # 0.10
}
```

**Validación en config.py:** Los pesos deben sumar 1.0 ± 0.01. Si no, el sistema falla en startup con `ConfigurationError`.

### Redistribución dinámica

Cuando un motor no está disponible, su peso se distribuye proporcionalmente a los demás:

```python
total_base = sum(base_weights.get(e, 0.0) for e in available)
weights = {e: base_weights.get(e, 0.0) / total_base for e in available}
```

**Ejemplo — RF no disponible:**
```
Antes:  supervised=0.40, iforest=0.30, lstm=0.20, rules=0.10
total_disponible = 0.30 + 0.20 + 0.10 = 0.60
Después: iforest=0.30/0.60=0.50, lstm=0.20/0.60=0.33, rules=0.10/0.60=0.17
```

### Pesos por tipo de ataque (`ATTACK_TYPE_WEIGHTS`)

Configuración en `.env`:
```
ATTACK_TYPE_WEIGHTS={"PortScan": {"rules": 0.50, "supervised": 0.30, "isolation_forest": 0.20, "lstm": 0.00},
                     "Bot": {"lstm": 0.50, "supervised": 0.30, "isolation_forest": 0.20, "rules": 0.00}}
```

Esto permite optimizar la sensibilidad del ensemble **por clase de ataque** sin reentrenar los modelos. Los overrides reemplazan los pesos base solo cuando el motor supervisado clasifica el tráfico con el `attack_type` especificado.

### Calibración por temperatura (Platt scaling)

```python
def _calibrate(score: float, temperature: float) -> float:
    if temperature == 1.0 or score <= 0.0 or score >= 1.0:
        return score
    logit = math.log(score / (1.0 - score))  # log(p/(1-p))
    scaled = logit / max(temperature, 1e-9)
    return 1.0 / (1.0 + math.exp(-scaled))   # sigmoid
```

**Efecto del parámetro `CALIBRATION_TEMPERATURE`:**

| Temperatura | Efecto | Cuándo usar |
|---|---|---|
| `< 1.0` | Sharpening: scores se acercan a 0 o 1 | Alto umbral de confianza, pocas FPs aceptadas |
| `= 1.0` | Sin cambio (default) | Calibración correcta del ensemble |
| `> 1.0` | Softening: scores se acercan a 0.5 | Modelo sobreconfiado, muchas FPs |

Para calibrar empíricamente, trazar el histograma de scores en tráfico normal: si el modo está por encima de 0.4, subir la temperatura; si está por debajo de 0.2, bajarla.

### Severidad

```python
def severity_from_score(score: float, attack_type: str | None = None) -> str:
    # Boost a critical para tipos de ataque severos
    if attack_type and attack_type not in ("BENIGN", None):
        critical_types = {"DDoS", "DoS", "Infiltration", "Web Attack"}
        if any(t in attack_type for t in critical_types) and score >= 0.70:
            return "critical"

    if score >= 0.85:   return "critical"
    if score >= 0.70:   return "high"
    if score >= 0.55:   return "medium"
    return "low"
```

Los ataques DoS, Infiltration y Web Attack tienen un umbral reducido para `critical` (0.70 en vez de 0.85), reflejando su mayor impacto operacional.

---

## 8. Pesos Adaptativos (Feedback Loop)

**Archivo:** `src/enrichment/adaptive_weights.py`

### Mecanismo

El sistema aprende de las etiquetas de los analistas. Cuando un analista etiqueta una alerta como falso positivo (notes contiene "false positive"), el sistema registra qué motor contribuyó más al score incorrecto.

**Fórmula de contribución relativa:**
```python
for e in engine_names:
    contribution = scores.get(e, 0.0) / total  # contribución proporcional
    if is_fp:
        fp_contrib[e] += contribution
    else:
        tp_contrib[e] += contribution
```

**Cálculo de nuevos pesos con Laplace smoothing:**
```python
for e in engine_names:
    tp = tp_contrib[e] + 1.0  # +1 para evitar división por cero
    fp = fp_contrib[e] + 1.0
    weights[e] = tp / (tp + fp)  # precision-like score por motor

# Normalizar a suma=1
total = sum(weights.values())
weights = {e: w / total for e, w in weights.items()}
```

**Requisitos para activar:**

| Parámetro | Default | Descripción |
|---|---|---|
| `ADAPTIVE_WEIGHTS_ENABLED` | `false` | Habilitar el mecanismo |
| `ADAPTIVE_MIN_SAMPLES` | 100 | Mínimo de alertas etiquetadas para computar pesos |

### Flujo operacional

```
1. Activar: ADAPTIVE_WEIGHTS_ENABLED=true en .env

2. Analistas etiquetan alertas durante 2–4 semanas:
   PATCH /api/alerts/{id} {"notes": "false positive — NAS backup", "acknowledged": true}
   PATCH /api/alerts/{id} {"notes": "confirmed DoS", "acknowledged": true}

3. Después de 100+ muestras:
   GET /api/adaptive-weights
   → {"suggested_weights": {"supervised": 0.48, "isolation_forest": 0.22, ...}}

4. Aplicar manualmente en .env:
   WEIGHT_SUPERVISED=0.48
   WEIGHT_IFOREST=0.22
   ...

5. Reiniciar CNDS para aplicar los nuevos pesos.
```

**Limitación importante:** El mecanismo actual es **no automático** — los pesos sugeridos deben aplicarse manualmente. Esto es intencional: los pesos del ensemble son una decisión operacional que un humano debe revisar antes de implementar.

---

## 9. Integración con MLflow

**Archivo:** `src/mlflow_registry.py`

### Configuración

```bash
MLFLOW_TRACKING_URI=http://mlflow-server:5000   # Servidor MLflow
MLFLOW_REGISTRY_NAME=cnds                        # Prefijo de modelo en registry
```

Cuando `MLFLOW_TRACKING_URI` está vacío, toda la funcionalidad MLflow se deshabilita silenciosamente y los motores cargan desde archivos locales.

### Registro de modelos

Todos los modelos ML son registrados bajo nombres con prefijo `cnds-`:

| Motor | Registry name | Función de carga |
|---|---|---|
| Random Forest | `cnds-supervised` | `mlflow.sklearn.load_model()` |
| Isolation Forest | `cnds-isolation_forest` | `mlflow.sklearn.load_model()` |
| LSTM Autoencoder | `cnds-lstm` | `mlflow.pytorch.load_model()` |

### Registrar un modelo entrenado

```python
from src.mlflow_registry import log_model, log_pytorch_model

# Random Forest / Isolation Forest (scikit-learn)
log_model(
    model         = pipeline,             # scikit-learn Pipeline o modelo
    artifact_path = "rf_model",
    model_name    = "supervised",         # → registrado como "cnds-supervised"
    metrics       = {                     # métricas opcionales del entrenamiento
        "accuracy": 0.987,
        "f1_weighted": 0.985,
        "test_samples": 56000,
    }
)

# LSTM Autoencoder (PyTorch)
log_pytorch_model(
    model         = lstm_model,
    artifact_path = "lstm_autoencoder",
    model_name    = "lstm",
    metrics       = {
        "val_reconstruction_error": 1.1037,
        "threshold": 1.1037,
        "training_hours": 8.0,
    }
)
```

### Ciclo de vida de versiones

MLflow maneja múltiples versiones por modelo. La función `load_latest()` carga por defecto el stage `"Production"`:

```python
model_uri = f"models:/{MLFLOW_REGISTRY_NAME}-{model_name}/Production"
```

**Proceso para promover una nueva versión:**
1. Entrenar el nuevo modelo.
2. Registrarlo con `log_model()` (crea version N en stage "None").
3. En MLflow UI o CLI: transicionar versión N a "Staging".
4. Validar con `pcap_replay.py` en tráfico de referencia.
5. Transicionar a "Production". CNDS cargará el nuevo modelo en el próximo restart.
6. Archivar la versión anterior.

---

## 10. Procedimientos de Entrenamiento

### 10.1 Random Forest — Entrenamiento inicial

**Paso 1: Obtener el dataset**

```bash
# Descargar CIC-IDS2017 desde cicresearch.ca
# El dataset MachineLearningCSV.zip contiene 8 archivos CSV (uno por día)
# Combinar en un solo archivo:
head -1 Monday-WorkingHours.pcap_ISCX.csv > combined.csv
tail -n +2 -q *.csv >> combined.csv
```

**Paso 2: Verificar compatibilidad de columnas**

```python
import pandas as pd
df = pd.read_csv("combined.csv")
df.columns = df.columns.str.strip()

from src.features.flow_extractor import FLOW_FEATURE_NAMES
missing = [c for c in FLOW_FEATURE_NAMES if c not in df.columns]
print("Missing:", missing)
# Si hay columnas faltantes, revisar el mapeo de nombres CICFlowMeter
```

**Paso 3: Entrenar**

```bash
# Modelo estándar (76 features)
python -c "
import pandas as pd, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from src.features.flow_extractor import FLOW_FEATURE_NAMES

df = pd.read_csv('combined.csv')
df.columns = df.columns.str.strip()
df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FLOW_FEATURE_NAMES)

X = df[FLOW_FEATURE_NAMES].values.astype(np.float32)
y = df['Label'].str.strip().values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('rf', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
])
pipeline.fit(X_train, y_train)
print(classification_report(y_test, pipeline.predict(X_test)))
dump(pipeline, 'models/rf_model.joblib')
print('Saved: models/rf_model.joblib')
"
```

**Paso 4 (opcional): Modelo extendido con payload (86 features)**

```bash
# Requiere dataset con columnas de payload ya extraídas
python scripts/retrain_with_payload.py \
    --dataset combined_with_payload.csv \
    --output models/rf_model_v2.joblib \
    --n-estimators 200
```

---

### 10.2 Isolation Forest — Entrenamiento inicial

**Paso 1: Capturar baseline**

```bash
# Capturar tráfico normal en producción (30–60 minutos mínimo)
sudo tcpdump -i eth0 -w baseline_normal.pcap -G 3600 -W 1

# O usar el replay script con PCAPs etiquetados como BENIGN
python scripts/pcap_replay.py --pcap baseline_normal.pcap --output-features baseline_features.json
```

**Paso 2: Extraer host features del baseline**

```python
# El replay script extrae features; para entrenamiento necesitas los vectores
import json, numpy as np
from src.features.host_extractor import HostExtractor

extractor = HostExtractor()
# Procesar paquetes del PCAP y acumular host features
# [código de captura de features...]
X_baseline = np.array(host_feature_vectors, dtype=np.float32)  # shape (N, 18)
```

**Paso 3: Entrenar IF + Scaler**

```python
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump
import numpy as np

X = X_baseline  # solo tráfico normal, shape (N, 18)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = IsolationForest(
    n_estimators  = 100,
    contamination = 0.01,   # 1% de puntos asumidos anómalos
    random_state  = 42,
    n_jobs        = -1,
)
model.fit(X_scaled)

dump(model,  'models/isolation_forest.joblib')
dump(scaler, 'models/if_scaler.joblib')
print(f"IF trained on {len(X)} samples")
print(f"Anomaly threshold: {model.threshold_:.4f}")
```

---

### 10.3 LSTM Autoencoder — Entrenamiento inicial

**Paso 1: Preparar secuencias**

```python
import numpy as np

# X_host_features: array (N, 18) de host features ordenados por tiempo, solo tráfico normal
# SEQ_LEN = 20 pasos temporales por secuencia

def make_sequences(X, seq_len=20):
    """Crear ventanas deslizantes de longitud seq_len."""
    sequences = []
    for i in range(len(X) - seq_len + 1):
        sequences.append(X[i:i+seq_len])
    return np.array(sequences, dtype=np.float32)  # shape (N-19, 20, 18)

sequences = make_sequences(X_host_features)  # shape (N-19, 20, 18)
```

**Paso 2: Definir arquitectura**

```python
import torch
import torch.nn as nn

class LSTMAutoencoder(nn.Module):
    def __init__(self, n_features=18, hidden_dim=64, latent_dim=32, num_layers=2, dropout=0.2):
        super().__init__()
        self.seq_len    = 20
        self.n_features = n_features

        self.encoder = nn.LSTM(
            input_size  = n_features,
            hidden_size = hidden_dim,
            num_layers  = num_layers,
            dropout     = dropout if num_layers > 1 else 0,
            batch_first = True,
        )
        self.latent = nn.Linear(hidden_dim, latent_dim)

        self.decoder = nn.LSTM(
            input_size  = latent_dim,
            hidden_size = hidden_dim,
            num_layers  = num_layers,
            dropout     = dropout if num_layers > 1 else 0,
            batch_first = True,
        )
        self.output_layer = nn.Linear(hidden_dim, n_features)

    def forward(self, x):
        # x: (batch, seq_len, n_features)
        enc_out, _ = self.encoder(x)              # (batch, seq_len, hidden_dim)
        latent = self.latent(enc_out)              # (batch, seq_len, latent_dim)
        dec_out, _ = self.decoder(latent)          # (batch, seq_len, hidden_dim)
        return self.output_layer(dec_out)          # (batch, seq_len, n_features)
```

**Paso 3: Entrenar**

```python
from torch.utils.data import DataLoader, TensorDataset, random_split
import json

# Parámetros
HIDDEN_DIM  = 64
LATENT_DIM  = 32
NUM_LAYERS  = 2
DROPOUT     = 0.2
EPOCHS      = 50
BATCH_SIZE  = 64
LR          = 1e-3
DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"

X_tensor = torch.tensor(sequences)  # (N, 20, 18)
dataset  = TensorDataset(X_tensor)

val_size   = int(0.1 * len(dataset))
train_size = len(dataset) - val_size
train_ds, val_ds = random_split(dataset, [train_size, val_size])

train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False)

model     = LSTMAutoencoder(hidden_dim=HIDDEN_DIM, latent_dim=LATENT_DIM,
                             num_layers=NUM_LAYERS, dropout=DROPOUT).to(DEVICE)
optimizer = torch.optim.Adam(model.parameters(), lr=LR)
criterion = nn.MSELoss()

best_val_loss = float('inf')
for epoch in range(EPOCHS):
    model.train()
    train_loss = 0.0
    for (batch,) in train_loader:
        batch = batch.to(DEVICE)
        optimizer.zero_grad()
        output = model(batch)
        loss   = criterion(output, batch)
        loss.backward()
        optimizer.step()
        train_loss += loss.item()

    model.eval()
    val_errors = []
    with torch.no_grad():
        for (batch,) in val_loader:
            batch    = batch.to(DEVICE)
            output   = model(batch)
            errors   = torch.mean((output - batch) ** 2, dim=(1, 2))
            val_errors.extend(errors.cpu().numpy().tolist())

    val_mse = np.mean(val_errors)
    if val_mse < best_val_loss:
        best_val_loss = val_mse
        torch.save(model.cpu(), 'models/lstm_autoencoder.pt')
        model.to(DEVICE)

    if (epoch + 1) % 10 == 0:
        print(f"Epoch {epoch+1}/{EPOCHS} — val_mse={val_mse:.6f}")

# Calcular threshold: percentil 99 del error de reconstrucción en validación
threshold = float(np.percentile(val_errors, 99))
print(f"Reconstruction threshold (p99): {threshold:.6f}")

# Guardar config
config = {
    "sequence_length": 20,
    "hidden_dim":      HIDDEN_DIM,
    "latent_dim":      LATENT_DIM,
    "num_layers":      NUM_LAYERS,
    "dropout":         DROPOUT,
    "n_features":      18,
    "threshold":       threshold,
    "saved_at":        datetime.now().isoformat(),
}
with open('models/lstm_config.json', 'w') as f:
    json.dump(config, f, indent=2)
print("Config saved: models/lstm_config.json")
```

---

## 11. Procedimientos de Reentrenamiento

### ¿Cuándo reentrenar?

| Señal | Modelo afectado | Acción |
|---|---|---|
| Tasa de FP aumenta en IF (muchos `isolation_forest high` no confirmados) | IF | Reentrenar IF con nuevo baseline |
| LSTM falla en detectar beaconing conocido | LSTM | Ajustar threshold o reentrenar |
| Nuevo tipo de ataque no clasificado por RF | RF | Añadir clase y reentrenar |
| Cambio mayor en topología de red | IF + LSTM | Reentrenar ambos con nuevo baseline |
| Nuevo patrón de CVE crítico | Rules | Añadir regex; no reentrenar |
| Degradación sostenida de F1 en replay | RF | Verificar distribución de features |

### 11.1 Reentrenar Random Forest

```bash
# Opción A: Solo 76 features (compatible con modelo original)
python -c "
# ... [código de entrenamiento estándar del paso 10.1] ...
dump(pipeline, 'models/rf_model_v2.joblib')
"

# Opción B: 86 features con payload (rompe compatibilidad — actualizar RF_MODEL_FILE)
python scripts/retrain_with_payload.py \
    --dataset combined_with_payload.csv \
    --output models/rf_model_v2.joblib \
    --n-estimators 200 \
    --test-size 0.2

# Validar el nuevo modelo antes de reemplazar el existente
python scripts/pcap_replay.py --pcap test_attacks.pcap --model-path models/rf_model_v2.joblib

# Si la validación es satisfactoria, activar:
# En .env: RF_MODEL_FILE=rf_model_v2.joblib
# Reiniciar CNDS
```

### 11.2 Reentrenar Isolation Forest

Indicado cuando la red cambia significativamente (nuevo servidor, migración a cloud, etc.):

```bash
# 1. Capturar nuevo baseline (sin ataques, durante al menos 60 minutos)
sudo tcpdump -i eth0 -w new_baseline.pcap -G 3600 -W 1

# 2. Extraer features y entrenar
python -c "
# [Extraer X_host_features del nuevo baseline]
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_host_features)

model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
model.fit(X_scaled)

dump(model,  'models/isolation_forest_v2.joblib')
dump(scaler, 'models/if_scaler_v2.joblib')
"

# 3. Activar en .env:
# IF_MODEL_FILE=isolation_forest_v2.joblib
# IF_SCALER_FILE=if_scaler_v2.joblib
```

### 11.3 Reentrenar LSTM Autoencoder

El LSTM es el modelo más sensible a cambios de red. Si la red cambia (horarios de trabajo, nuevas aplicaciones), el threshold puede desajustarse.

**Opción 1: Solo reajustar threshold (sin reentrenar)**

```python
# Si el modelo está bien pero hay muchas FPs o FNs, ajustar threshold en config
import json

with open('models/lstm_config.json') as f:
    config = json.load(f)

# Subir threshold → menos FPs (más permisivo)
# Bajar threshold → menos FNs (más agresivo)
config['threshold'] = 1.5  # ajustar según observación

with open('models/lstm_config.json', 'w') as f:
    json.dump(config, f, indent=2)
# Reiniciar CNDS para aplicar
```

**Opción 2: Reentrenamiento completo**

```bash
# Seguir el procedimiento del paso 10.3 con nuevo baseline
# El threshold se recalcula automáticamente como percentil 99
# Reemplazar lstm_autoencoder.pt y lstm_config.json
```

### 11.4 Versionado con MLflow (proceso recomendado para producción)

```bash
# Después de entrenar un nuevo modelo:
python -c "
from src.mlflow_registry import log_model

# Cargar modelo nuevo
from joblib import load
new_model = load('models/rf_model_v2.joblib')

# Registrar
uri = log_model(
    model         = new_model,
    artifact_path = 'rf_model_v2',
    model_name    = 'supervised',
    metrics       = {'f1_weighted': 0.988, 'test_samples': 72000}
)
print('Registered:', uri)
"

# En MLflow UI: transicionar de None → Staging → (validar) → Production
# CNDS cargará automáticamente la nueva versión Production al reiniciar
```

---

## 12. Evaluación de Modelos

**Archivo:** `scripts/pcap_replay.py`

### Métricas disponibles

```python
@dataclass
class EvalResult:
    tp: int   # Verdaderos positivos
    fp: int   # Falsos positivos
    tn: int   # Verdaderos negativos
    fn: int   # Falsos negativos

    @property
    def precision(self):  return self.tp / max(self.tp + self.fp, 1)
    @property
    def recall(self):     return self.tp / max(self.tp + self.fn, 1)
    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 1e-9)
    @property
    def accuracy(self):
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / max(total, 1)
```

### Evaluación con PCAP etiquetado

```bash
# Reproducir un PCAP conocido y comparar contra ground truth
python scripts/pcap_replay.py \
    --pcap test_attacks.pcap \
    --output results.json \
    --ground-truth labels.csv    # CSV con columnas: flow_key, is_attack (0/1)
```

### Evaluación con el digital twin

```bash
cd demo
python run_demo.py --output-json demo_results.json
```

La salida JSON contiene scores por escenario, detecciones, falsos positivos del tráfico normal y técnicas MITRE observadas.

### Benchmark de rendimiento mínimo recomendado

| Escenario | Detection rate mínima | FP rate máxima |
|---|---|---|
| ICMP Flood | 99% | < 1% |
| SYN Scan (>50 SYNs) | 95% | < 2% |
| Brute Force SSH/FTP | 85% | < 5% |
| Web SQLi/XSS | 90% | < 3% |
| Data Exfiltration (lenta) | 70% | < 5% |
| Tráfico normal | — | < 2% |

Si un modelo recién entrenado no alcanza estos umbrales en `pcap_replay.py`, no debería promoverse a producción.

---

## 13. Referencia de Hiperparámetros

Todos los parámetros configurables vía `.env`, con sus valores por defecto y sus efectos:

### Parámetros del Ensemble

| Variable | Default | Rango | Efecto al aumentar |
|---|---|---|---|
| `WEIGHT_SUPERVISED` | 0.40 | [0, 1] | Más peso al RF (mayor precisión en ataques conocidos) |
| `WEIGHT_IFOREST` | 0.30 | [0, 1] | Más sensible a anomalías volumétricas |
| `WEIGHT_LSTM` | 0.20 | [0, 1] | Más sensible a comportamiento temporal |
| `WEIGHT_RULES` | 0.10 | [0, 1] | Más sensible a patrones de umbral |
| `ENSEMBLE_THRESHOLD` | 0.55 | [0, 1] | Bajar → más FPs, más detección; Subir → menos FPs, más FNs |
| `CALIBRATION_TEMPERATURE` | 1.0 | (0, 10] | Bajar → sharper scores; Subir → softer scores |

### Parámetros del Random Forest

| Variable | Default | Descripción |
|---|---|---|
| RF `n_estimators` | 100 | Solo en script de entrenamiento (`--n-estimators`) |
| RF `random_state` | 42 | Semilla de reproducibilidad |
| RF `test_size` | 0.2 | Fracción de test (`--test-size`) |

### Parámetros del Isolation Forest

| Variable | Default | Descripción |
|---|---|---|
| IF `contamination` | 0.01 | Fracción de anomalías asumida en training data |
| IF sigmoid steepness | 5.0 | Hardcoded en `isolation_forest.py:score()` |

### Parámetros del LSTM

| Clave en lstm_config.json | Valor actual | Descripción |
|---|---|---|
| `sequence_length` | 20 | Pasos temporales por secuencia |
| `hidden_dim` | 64 | Dimensión del estado oculto LSTM |
| `latent_dim` | 32 | Dimensión de la representación latente |
| `num_layers` | 2 | Capas LSTM apiladas |
| `dropout` | 0.2 | Dropout entre capas LSTM |
| `threshold` | 1.1037 | MSE máximo normal (percentil 99 en validación) |

### Parámetros de Extracción

| Variable | Default | Efecto |
|---|---|---|
| `FLOW_TIMEOUT` | 120s | Más largo → features más completos; más memoria |
| `ACTIVE_IDLE_THRESH` | 1.0s | Gap que separa períodos activos/inactivos |
| `MIN_PACKETS_FOR_ML` | 10 | Mínimo de paquetes antes de inferencia |
| `HOST_WINDOW_SIZE` | 100 | Más grande → estadísticas más estables |
| `MAX_TRACKED_IPS` | 5,000 | Más grande → más estado en memoria |
| `MAX_ACTIVE_FLOWS` | 50,000 | Límite de flujos concurrentes |

### Umbrales de Reglas

| Variable | Default | Notas |
|---|---|---|
| `ICMP_FLOOD_THRESHOLD` | 50 | Paquetes ICMP en el flujo acumulado |
| `PORT_SCAN_THRESHOLD` | 20 | SYN flags para detectar scan |
| `LARGE_PAYLOAD_BYTES` | 10,000 | Tamaño máximo payload forward |
| Ratio asimétrico | 50 | Hardcoded en `rules.py`: fwd_bytes/bwd_bytes |

### Parámetros de Pesos Adaptativos

| Variable | Default | Descripción |
|---|---|---|
| `ADAPTIVE_WEIGHTS_ENABLED` | `false` | Activar mecanismo de adaptación |
| `ADAPTIVE_MIN_SAMPLES` | 100 | Alertas etiquetadas mínimas |
