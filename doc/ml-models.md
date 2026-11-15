# CNDS — Modelos de ML/AI: Entrenamiento y Reentrenamiento

Este documento cubre en detalle los modelos de machine learning del sistema — el motor supervisado unificado FT-Transformer (con Random Forest como fallback), Isolation Forest y LSTM Autoencoder — su ingeniería de features, los parámetros exactos de configuración, los procedimientos de entrenamiento inicial y reentrenamiento, la calibración del ensemble, el sistema de pesos adaptativos y la integración con MLflow.

---

## Índice

1. [Visión general del pipeline de ML](#1-visión-general-del-pipeline-de-ml)
2. [Ingeniería de Features](#2-ingeniería-de-features)
   - 2.1 [76 Flow Features (CICFlowMeter)](#21-76-flow-features-cicflowmeter)
   - 2.2 [18 Host Features](#22-18-host-features)
   - 2.3 [10 Payload Features](#23-10-payload-features)
3. [Modelo 1: Supervisado (FT-Transformer + Random Forest)](#3-modelo-1-supervisado-ft-transformer-preferido--random-forest-fallback)
   - 3.0 [FT-Transformer (preferido)](#30-ft-transformer-preferido-producción-2026-05-04)
   - 3.1 [Random Forest (fallback)](#31-random-forest-fallback)
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
│      Inference (al expirar el flujo, hasta 5 motores)       │
│                                                             │
│  FT-T ─── 76 flow features ──────→ (attack_type, conf)     │  ← preferido
│  RF   ─── 76 flow features ──────→ (attack_type, conf)     │  ← fallback sin ckpt
│  IF   ─── 18 host features ──────→ anomaly_score [0,1]     │
│  LSTM ─── seq de 20 × 18 feat. ──→ reconstruction_error    │
│  Rules ── flujo + payload + JA3 ─→ (1.0 si regla dispara)  │
│  Baseline ─ 18 host features ───→ anomaly_score [0,1]      │  ← entrenado en vivo
└──────────────┬──────────────────────────────────────────────┘
               │ EngineScores
               ▼
┌─────────────────────────────────────────────────────────────┐
│               EnsembleScorer                                │
│                                                             │
│  weighted_avg(supervised, iforest, lstm, rules, baseline)  │
│  → +0.30 si hay hit de threat intel; CRITICAL_RULES → 1.0  │
│  → temperature scaling (Platt)                             │
│  → umbral ENSEMBLE_THRESHOLD (0.55)                        │
│  → severidad (low/medium/high/critical)                    │
└─────────────────────────────────────────────────────────────┘
```

Los modelos ML operan sobre **representaciones de features distintas** y detectan **tipos de amenaza complementarios**:

| Modelo | Input | Detecta | Requisito |
|---|---|---|---|
| FT-Transformer (preferido) | 76 flow features | 10 clases UNSW-NB15 | Checkpoint `unified_ft_transformer.pt` |
| Random Forest (fallback) | 76 flow features | Ataques conocidos con nombre | Sin checkpoint FT-T disponible |
| Isolation Forest | 18 host features | Anomalías volumétricas/comportamentales | Tráfico normal de referencia |
| LSTM Autoencoder | Secuencias temporales 20×18 | Cambios lentos / beaconing | Tráfico normal de al menos 2h |
| Baseline (IF + LSTM entrenados en vivo) | 18 host features | Desviación respecto a lo normal en esta red | Una ventana entrenada por `src/unsupervised/` (ver [unsupervised.md](unsupervised.md)) |

---

## 2. Ingeniería de Features

### 2.1 76 Flow Features (CICFlowMeter)

**Archivo:** `src/features/flow_extractor.py`

Los features de flujo replican el esquema de CICFlowMeter (76 columnas, el mismo que usa la redistribución CIC de **UNSW-NB15** con la que se entrenan los modelos). Los nombres en código son snake_case; los CSV de CICFlowMeter usan otros nombres (`Flow Duration`, ...), así que la correspondencia es por posición.

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
| `MAX_ACTIVE_FLOWS` | 50,000 | Techo de flujos concurrentes (al llegar se expulsa el flujo más antiguo) |
| `MIN_PACKETS_FOR_ML` | 10 | Definido en `src/config.py`, pero ningún código en ejecución lo lee |
| `MAX_PAYLOAD_SAMPLES` | 50 | Samples de payload guardados por flujo |
| `PAYLOAD_SAMPLE_BYTES` | 4,096 | Bytes por sample de payload |

**Invariante:** el extractor comprueba que el vector resultante tenga exactamente 76 elementos; si no, retorna `None` y el flujo no se envía a los motores.

### Extensión a 86 features (con payload)

Al ejecutar el script de reentrenamiento con payload, se concatenan los 10 `PAYLOAD_FEATURE_NAMES` al final del vector de 76, produciendo un vector de 86 features. El motor supervisado detecta automáticamente el tamaño al cargar el modelo:

```python
n = _get_n_features(self._model)
self._expects_payload = (n == len(EXTENDED_FEATURE_NAMES))  # 76 + 10 = 86
```

Esto solo aplica al Random Forest (`SupervisedEngine`). El FT-Transformer usa siempre los 76 features de flujo.

---

### 2.2 18 Host Features

**Archivo:** `src/features/host_extractor.py`

Los host features agregan el comportamiento de una IP fuente a lo largo de una ventana deslizante de los últimos `HOST_WINDOW_SIZE` (default: 100) paquetes. Son la entrada para Isolation Forest, LSTM Autoencoder y el motor baseline.

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
    "session_duration",        # 9: duración de la ventana (hasta "ahora")

    # ── Protocolo (3) ────────────────────────────────────────────────
    "tcp_ratio",               # 10: fracción de paquetes TCP
    "udp_ratio",               # 11: fracción de paquetes UDP
    "icmp_ratio",              # 12: fracción de paquetes ICMP

    # ── Puertos (2) ──────────────────────────────────────────────────
    "unique_ports",            # 13: número de puertos destino distintos
    "uncommon_port_ratio",     # 14: puertos fuera de COMMON_PORTS / total

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
- **Evicción**: cuando se alcanza `MAX_TRACKED_IPS` (5,000), `HostExtractor` expulsa la IP cuyo último paquete es más antiguo. El LSTM tiene su propio límite y expulsa la IP con el buffer más corto.
- **Esquema 2**: las tasas, totales y `session_duration` se calculan sobre la ventana deslizante de los últimos `HOST_WINDOW_SIZE` paquetes, no desde que se vio la IP por primera vez (ver "Host feature schema" en [unsupervised.md](unsupervised.md)).

**`COMMON_PORTS`** usados para calcular `uncommon_port_ratio`:
```python
COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443}
```

---

### 2.3 10 Payload Features

**Archivo:** `src/features/payload_analyzer.py`

Extraídos de los bytes crudos del payload forward del flujo. Se pasan al motor supervisado (si fue entrenado con 86 features) y al Rules Engine.

**Índices 0–5: flags binarios de patrones**

| Índice | Nombre | Patrón regex |
|---|---|---|
| 0 | `has_sqli` | `union select`, `drop table`, `' or `, `'='`, `'--`, `'; drop ...`, `xp_cmdshell`, etc. |
| 1 | `has_xss` | `<script`, `javascript:`, `onerror=`, `onload=`, `<img `, `<svg `, `alert(` |
| 2 | `has_cmdi` | Un operador de shell (`;`, `\|`, `&&`, backtick, `$(`) seguido de un comando conocido (`ls`, `cat`, `curl`, `bash`, ...) y un delimitador |
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

**Coste acotado (no hay timeout por patrón):**

- Solo se analizan los primeros `PAYLOAD_SAMPLE_BYTES` (4096) de cada paquete, y como mucho `MAX_PAYLOAD_SAMPLES` (50) muestras por flujo.
- Una única regex combinada (`_PRESCREEN`) se ejecuta primero; los seis patrones solo se prueban si esa pre-criba encuentra algo.
- Los payloads que parecen cifrados o comprimidos se saltan (`looks_encrypted()`: cabecera de registro TLS, o al menos 256 bytes con entropía ≥ 7.0 bits/byte).

---

## 3. Modelo 1: Supervisado (FT-Transformer preferido + Random Forest fallback)

El slot supervisado tiene dos implementaciones intercambiables. Ambas
consumen el mismo vector de 76 features de flujo CICFlowMeter y devuelven
`(label, confidence)` desde `predict()`, que es el único método que usan el
pipeline y `POST /api/predict`: el score supervisado es `0.0` si la clase es
benigna y la confianza de la clase predicha en caso contrario. Ambos tienen
también `anomaly_score()` (`1 − P(Benign)` con umbral), pero ningún camino en
ejecución lo llama. El registry elige **FT-Transformer cuando hay
checkpoint disponible**, en caso contrario degrada al pipeline Random
Forest. Ambos motores comparten la misma interfaz, por lo que el
`pipeline.py`, el ensemble y la API funcionan sin cambios.

### 3.0 FT-Transformer (preferido, producción 2026-05-04)

**Archivos:** `src/engines/ft_transformer_engine.py`, `src/models/ft_transformer.py`
**Checkpoint local:** `models/unified/unified_ft_transformer.pt`
**MLflow registry:** modelo `ml-ids-unified-ft-transformer`, stage `MLFLOW_FT_STAGE`

#### Arquitectura

FT-Transformer (Gorishniy et al., NeurIPS 2021) — tokenizador affine por
feature + 3 bloques transformer encoder Pre-LN + cabeza linear. Total
~1.6M parámetros. Hiperparámetros tunados con Optuna (25 trials,
TPESampler + MedianPruner):

```python
{'d_token': 256, 'n_blocks': 3, 'n_heads': 8, 'ff_factor': 2.0,
 'dropout': 0.0985, 'lr': 3.9e-4, 'weight_decay': 7.15e-5,
 'batch_size': 2048, 'class_weight': 'sqrt_inverse', 'use_focal': False}
```

**Diagramas de la arquitectura:** ver
[`ML-IDS/docs/UNIFIED_MODEL_ARCHITECTURE.md`](https://github.com/RobertoDeLaCamara/ML-IDS/blob/main/docs/UNIFIED_MODEL_ARCHITECTURE.md)
(6 diagramas Mermaid: data flow, tokenizer, encoder block, parameter
budget, runtime integration, atención por ejemplo).

#### Dataset y etiquetas

Entrenado sobre el redistribución CIC del UNSW-NB15 (carpeta nombrada
`CIC-IDS2017/` por convención histórica, contenido es UNSW-NB15). 10
clases:

| id | label |
|---|---|
| 0 | Benign |
| 1 | Analysis |
| 2 | Backdoor |
| 3 | DoS |
| 4 | Exploits |
| 5 | Fuzzers |
| 6 | Generic |
| 7 | Reconnaissance |
| 8 | Shellcode |
| 9 | Worms |

Tupla expuesta como `UNIFIED_CLASS_LABELS` en
`cnds/src/models/ft_transformer.py`.

#### Métricas

- **Test F1 macro:** 0.6197 (full test split, 67k filas).
- **Smoke test reproducible:** 0.6194 vía
  `scripts/smoke_test_ft_unified.py` (delta 0.0003).
- **Comparativa:** XGBoost baseline 0.6095, FT-T default 0.5446. La
  ganancia +1.0 punto macro viene mayoritariamente de clases minoritarias
  (Backdoor 0.44→0.58, Generic 0.65→0.75, Worms 0.34→0.46).

#### Inferencia

```python
import numpy as np
from src.engines.ft_transformer_engine import FTTransformerEngine

engine = FTTransformerEngine()        # carga MLflow → fallback local
label, conf = engine.predict(flow_vec_76)         # ('DoS', 0.91)
score       = engine.anomaly_score(flow_vec_76)   # 1 - P(Benign) con umbral; no se usa en ejecución
```

Pipeline interno (autocast bfloat16 si CUDA disponible):

```python
x = np.nan_to_num(x.astype(np.float32), nan=0, posinf=1e9, neginf=-1e9)
x = scaler.transform(x).astype(np.float32)
with torch.inference_mode():
    if cuda: with torch.amp.autocast('cuda', dtype=torch.bfloat16): logits = model(x)
    else:    logits = model(x)
    if FT_TEMPERATURE != 1.0:
        logits = logits / FT_TEMPERATURE   # temperature scaling — reduce over-confidence
probs = logits.softmax(-1)
```

##### Nota sobre temperature scaling

Los modelos Transformer clasificadores tienden a ser sistemáticamente sobreconfiados: sus probabilidades máximas se agrupan cerca de 1.0 incluso para flujos ambiguos. `FT_TEMPERATURE=2.0` divide los logits por 2 antes del softmax, suavizando la distribución de probabilidades (la confianza máxima típica baja de ~0.97 a ~0.85). Esto mejora la calibración del ensemble: el motor supervisado ya no domina el score ponderado en todos los flujos.

Para desactivar: `FT_TEMPERATURE=1.0`. Para calibrar empíricamente, graficar el histograma de `P(predicted_class)` sobre tráfico benigno conocido — si el modo supera 0.90, aumentar la temperatura; si el percentil 50 cae por debajo de 0.60 en ataques conocidos, reducirla.

#### Cadena de carga (orden de prioridad)

| Prioridad | Fuente | Cuándo |
|---|---|---|
| 1 | MLflow registry | `MLFLOW_TRACKING_URI` configurado y artefacto registrado |
| 2 | `models/unified/unified_ft_transformer.pt` + `unified_scaler.pkl` | Checkpoint local copiado desde ML-IDS |

Si ninguno disponible el motor se autodeshabilita y el registry degrada
al Random Forest descrito abajo.

#### Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `FT_MODEL_FILE` | `unified/unified_ft_transformer.pt` | Path relativo a `MODELS_DIR` |
| `FT_SCALER_FILE` | `unified/unified_scaler.pkl` | StandardScaler emparejado |
| `FT_USE_GPU` | `false` | Inferencia en CUDA si disponible |
| `FT_SCORE_THRESHOLD` | `0.50` | Umbral de `anomaly_score()` (1 − P(Benign)). Sin efecto hoy: ningún camino en ejecución llama a ese método |
| `FT_TEMPERATURE` | `2.0` | Factor de temperature scaling aplicado a logits antes de softmax (T > 1 reduce over-confidence; 1.0 desactiva). Ver [sección de calibración](#nota-sobre-temperature-scaling). |
| `MLFLOW_FT_REGISTRY_NAME` | `ml-ids-unified-ft-transformer` | Nombre del modelo registrado en MLflow |
| `MLFLOW_FT_STAGE` | `None` | Stage de MLflow del que se toma la versión (por defecto el stage `None`, el de las versiones recién registradas) |

#### Smoke test y validación

```bash
# Reproducir F1 macro sobre el test split completo (~64 s en CPU)
python scripts/smoke_test_ft_unified.py --device cpu --data-dir /ruta/al/dataset

# Tests de integración (carga, predicciones, validación dataset-driven)
pytest tests/test_ft_transformer_engine.py -v   # 7 tests

# Runbook live (hping3/nmap manual, requiere root e iface):
# doc/UNIFIED_FT_LIVE_RUNBOOK.md
```

---

### 3.1 Random Forest (fallback)

**Archivo:** `src/engines/supervised.py`
**Modelo:** `models/rf_model.joblib` (completo, no versionado) o `models/rf_lite_model.joblib` (incluido en el repo)

### Arquitectura del modelo

El joblib contiene un `sklearn.pipeline.Pipeline` con cuatro etapas (`scripts/train_rf.py`):

```
Pipeline
├── ("clip")       → ClipNegativeTransformer    — recorta valores negativos
├── ("log1p")      → SelectiveLog1pTransformer  — log1p en features muy sesgados (|skew| > 5)
├── ("scaler")     → StandardScaler             — normalización z-score
└── ("classifier") → RandomForestClassifier
```

Al ir el preprocesado dentro del Pipeline, en inferencia los features se transforman con los parámetros del conjunto de entrenamiento, no con los del tráfico en tiempo real.

### Dataset de entrenamiento: UNSW-NB15 (redistribución CIC)

El Random Forest se entrena con el mismo dataset que el FT-Transformer: la redistribución del Canadian Institute for Cybersecurity de **UNSW-NB15** (~447k flujos etiquetados, 76 features CICFlowMeter, 10 clases; la carpeta local se llama `CIC-IDS2017/` por motivos históricos). `train_rf.py` espera dos ficheros en `--data-dir`: `Data.csv` (los 76 features) y `Label.csv` (columna `Label` con el índice de clase).

Las clases son las de la tabla del apartado 3.0 (`Benign`, `Analysis`, `Backdoor`, `DoS`, `Exploits`, `Fuzzers`, `Generic`, `Reconnaissance`, `Shellcode`, `Worms`). Las etiquetas de CIC-IDS2017 (`PortScan`, `DoS Hulk`, `SSH-Patator`, ...) no las emite ningún modelo incluido.

**Desbalanceo:** `Benign` es ~80 % de las muestras. `train_rf.py` sobremuestrea con SMOTE las clases minoritarias (se desactiva con `--no-smote`) y hace el split estratificado.

### Hiperparámetros de entrenamiento

| Parámetro | Modelo completo (`train_rf.py`) | Modelo lite (`--lite`) |
|---|---|---|
| `n_estimators` | 200 (`--estimators`) | 25 |
| `max_depth` | 20 (`--max-depth`) | 10 |
| `min_samples_leaf` / `min_samples_split` | 2 / 5 | 2 / 5 |
| Muestras | todas (~447k) | 50,000 estratificadas, sin SMOTE |
| `test_size` | 0.20 (`--test-size`) | 0.20 |

El modelo lite (1.6 MB, accuracy 0.91 según `models/rf_lite_model_meta.json`) es el que se incluye en el repositorio. `scripts/retrain_with_payload.py` es un script distinto: entrena un Pipeline `StandardScaler` + `RandomForestClassifier` (100 árboles por defecto, `--n-estimators`) sobre 86 features a partir de un CSV con columna `Label`.

### Inferencia

```python
def predict(self, flow_features, payload_features=None):
    # Construir vector
    vec = flow_features  # shape (76,)
    if self._expects_payload and payload_features is not None:
        vec = np.concatenate([flow_features, payload_features])  # shape (86,)

    vec = vec.ravel().reshape(1, -1)
    label = self._model.predict(vec)[0]       # clase predicha
    proba = self._model.predict_proba(vec)[0]  # probabilidades por clase
    confidence = float(proba.max())            # confianza = prob de la clase ganadora
    return str(label), confidence
```

**Conversión a score para el ensemble** (en `src/pipeline.py` y `routers/predict.py`):
- Si la etiqueta es benigna (`is_benign(label)`, sin distinguir mayúsculas) → `score = 0.0`
- Si no → `score = confidence` (la probabilidad de la clase de ataque)

`RF_SCORE_THRESHOLD` (0.90) solo actúa dentro de `anomaly_score()`, que no se llama en ejecución.

### Carga y degradación

Orden de carga en `SupervisedEngine._load()`:

1. MLflow registry (`cnds-supervised`, stage `Production`), si `MLFLOW_TRACKING_URI` está configurado.
2. `models/rf_model.joblib` (`RF_MODEL_FILE`), el modelo completo entrenado localmente.
3. `models/rf_lite_model.joblib`, el modelo lite incluido en el repo.
4. Si no hay ninguno, el motor queda deshabilitado (`is_available = False`).

Los joblib locales se cargan con `model_integrity.load_joblib()`, que según `MODEL_INTEGRITY_MODE` comprueba el fichero contra `models/MANIFEST.sha256`.

---

## 4. Modelo 2: Isolation Forest (No Supervisado)

**Archivos:** `src/engines/isolation_forest.py`
**Modelos:** `models/isolation_forest.joblib` + `models/if_scaler.joblib` (no incluidos en el repo; `scripts/generate_demo_models.py` crea unos de demostración con datos sintéticos). Con MLflow configurado se intenta antes `cnds-isolation_forest` en stage `Production`.

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
│  → Linear(64 → 32) por paso     │
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

**Contenido de `models/lstm_config.json`** (incluido en el repo; el fichero de pesos `.pt` no lo está):

```json
{
  "sequence_length": 20,
  "hidden_dim":      64,
  "latent_dim":      32,
  "num_layers":      2,
  "dropout":         0.2,
  "n_features":      18,
  "reconstruction_threshold": 2.9730082154273987
}
```

### Buffers por IP

El LSTM no procesa paquetes individuales; mantiene una **cola FIFO por IP fuente**:

```python
self._buffers: dict[str, deque] = defaultdict(
    lambda: deque(maxlen=self._seq_len)  # maxlen=20
)
```

- Cada vez que expira un flujo de la IP `X`, se añade su vector de 18 host features al deque (un vector por flujo, no por paquete).
- El deque tiene `maxlen=20` → los features más antiguos se descartan automáticamente.
- Cuando el deque está **lleno** (exactamente 20 vectores), se ejecuta el autoencoder.

**Cold-start:** Los primeros 19 flujos de cualquier IP nueva no producen score LSTM real: `anomaly_score()` devuelve `0.0`, y ese cero entra en la mezcla con todo el peso del LSTM. El peso solo se redistribuye cuando el motor no está disponible (sin modelo cargado).

**Evicción:** Cuando `len(self._buffers) >= MAX_TRACKED_IPS`, el IP con el buffer más corto (menos datos) es expulsado:

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

    # Normalizar con reconstruction_threshold de lstm_config.json
    score = min(error / max(self._threshold, 1e-9), 1.0)
    return float(score)
```

**Threshold de reconstrucción:** la clave `reconstruction_threshold` de `lstm_config.json` (2.973 en el fichero incluido; 0.1 si la clave falta) es el punto de normalización: un error igual o superior produce score=1.0 y los errores menores producen scores en (0, 1). El motor no lee una clave llamada `threshold`.

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
| `syn_scan` | `syn_flag_cnt > PORT_SCAN_THRESHOLD AND fwd_act_data_pkts < 5` | `PORT_SCAN_THRESHOLD=20` |
| `port_scan` | una fuente inicia conexiones TCP (SYN sin ACK) a >= `HOST_SCAN_PORTS` puertos destino distintos de un mismo destino dentro de `HOST_SCAN_WINDOW_SECS` (`ScanTracker`, decidida entre flujos) | `HOST_SCAN_PORTS=15`, `HOST_SCAN_WINDOW_SECS=60`, `HOST_SCAN_ALLOWLIST` |
| `large_payload` | `max(fwd_lengths) > LARGE_PAYLOAD_BYTES` | `LARGE_PAYLOAD_BYTES=10000` |
| `payload:*` | Cualquier match de los 6 patrones de payload | — (regex fijos) |
| `asymmetric_upload` | más de 10 paquetes forward, al menos 1 backward y `sum(fwd_bytes) / max(sum(bwd_bytes),1) > 50` | Hardcoded ratio=50 |
| `malicious_ja3` | `ja3_hash in malicious_set` | Lista en `MALICIOUS_JA3_FILE` |

Las reglas listadas en `CRITICAL_RULES` (por defecto las seis `payload:*`, `malicious_ja3`, `syn_scan` y `port_scan`) fuerzan el score a 1.0 y generan alerta con independencia de la mezcla ponderada.

**Nota:** Los valores default son **más conservadores** de lo que parecen. Por ejemplo, `ICMP_FLOOD_THRESHOLD=50` significa 50 paquetes en el flujo acumulado, no 50/segundo. Para redes con alto tráfico ICMP legítimo (monitoreo Nagios, etc.), conviene subirlo a 200–500.

---

## 7. Ensemble Scorer: Fusión y Calibración

**Archivo:** `src/ensemble/scorer.py`

### Pesos base

```python
_BASE_WEIGHTS = {
    "supervised":       WEIGHT_SUPERVISED,    # 0.30 (config.py default; .env.example: 0.40)
    "isolation_forest": WEIGHT_IFOREST,       # 0.20 (.env.example: 0.10)
    "lstm":             WEIGHT_LSTM,          # 0.10 (.env.example: 0.00)
    "rules":            WEIGHT_RULES,         # 0.25 (.env.example: 0.20)
    "baseline":         WEIGHT_BASELINE,      # 0.15 (.env.example: 0.30)
}
```

**Validación en config.py:** Los pesos deben sumar 1.0 ± 0.01. Si no, el sistema falla en startup con `ConfigurationError`.

### Redistribución dinámica

Cuando un motor no está disponible (su score es `None`; un `0.0` cuenta como disponible), su peso se distribuye proporcionalmente a los demás:

```python
total_base = sum(base_weights.get(e, 0.0) for e in available)
weights = {e: base_weights.get(e, 0.0) / total_base for e in available}
```

**Ejemplo — motor supervisado no disponible:**
```
Antes:  supervised=0.30, iforest=0.20, lstm=0.10, rules=0.25, baseline=0.15
total_disponible = 0.20 + 0.10 + 0.25 + 0.15 = 0.70
Después: iforest=0.20/0.70≈0.29, lstm=0.10/0.70≈0.14, rules=0.25/0.70≈0.36, baseline=0.15/0.70≈0.21
```

### Pesos por tipo de ataque (`ATTACK_TYPE_WEIGHTS`)

Configuración en `.env`:
```
ATTACK_TYPE_WEIGHTS={"DoS": {"supervised": 0.60, "rules": 0.20}, "Reconnaissance": {"rules": 0.50}}
```

Esto permite optimizar la sensibilidad del ensemble **por clase de ataque** sin reentrenar los modelos. Los overrides reemplazan los pesos base de los motores que nombran solo cuando el motor supervisado clasifica el tráfico con ese `attack_type` (la clave debe coincidir con la etiqueta que emite el modelo: clases UNSW-NB15 con los modelos incluidos). No se valida que sumen 1.0; se renormalizan sobre los motores con score.

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
    if attack_type and not is_benign(attack_type):
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

El sistema calcula pesos sugeridos a partir de las etiquetas de los analistas. Una alerta reconocida (`acknowledged`) cuenta como falso positivo si su `label` es `fp` o sus notas contienen "false positive"; cualquier otra alerta reconocida cuenta como verdadero positivo. El cálculo cubre cuatro motores (`supervised`, `isolation_forest`, `lstm`, `rules`); el baseline no entra.

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
   PATCH /api/alerts/{id} {"label": "fp", "notes": "NAS backup", "acknowledged": true}
   PATCH /api/alerts/{id} {"label": "tp", "notes": "confirmed DoS", "acknowledged": true}

3. Después de 100+ muestras:
   GET /api/adaptive-weights
   → {"status": "ok", "weights": {"supervised": 0.31, "isolation_forest": 0.17, "lstm": 0.27, "rules": 0.25}}
   (antes de llegar al mínimo: {"status": "insufficient_data", "weights": null})

4. Aplicar manualmente en .env, dejando sitio a WEIGHT_BASELINE para que los
   cinco pesos sumen 1.0:
   WEIGHT_SUPERVISED=0.27
   WEIGHT_IFOREST=0.14
   ...

5. Reiniciar CNDS para aplicar los nuevos pesos.
```

**Limitación importante:** El mecanismo actual es **no automático** — los pesos sugeridos deben aplicarse manualmente. Esto es intencional: los pesos del ensemble son una decisión operacional que un humano debe revisar antes de implementar.

---

## 9. Integración con MLflow

**Archivo:** `src/mlflow_registry.py`

### Configuración

```bash
MLFLOW_TRACKING_URI=http://mlflow-server:5050   # Servidor MLflow (vacío = deshabilitado)
MLFLOW_REGISTRY_NAME=cnds                        # Prefijo de modelo en registry
```

Cuando `MLFLOW_TRACKING_URI` está vacío, toda la funcionalidad MLflow se deshabilita silenciosamente y los motores cargan desde archivos locales.

### Registro de modelos

Estos modelos se registran bajo nombres con prefijo `cnds-` (`MLFLOW_REGISTRY_NAME`):

| Motor | Registry name | Función de carga |
|---|---|---|
| Random Forest | `cnds-supervised` | `mlflow.sklearn.load_model()` |
| Isolation Forest | `cnds-isolation_forest` | `mlflow.sklearn.load_model()` |
| LSTM Autoencoder | `cnds-lstm` | `mlflow.pytorch.load_model()` |
| FT-Transformer | `ml-ids-unified-ft-transformer` (`MLFLOW_FT_REGISTRY_NAME`) | descarga del bundle `.pt` |
| Baseline (IF + LSTM en vivo) | `cnds-unsupervised-baseline` | artefactos de `src/unsupervised/` |

### Registrar un modelo entrenado

```python
from src.mlflow_registry import log_model, log_pytorch_model

# Random Forest / Isolation Forest (scikit-learn)
log_model(
    model         = pipeline,             # scikit-learn Pipeline o modelo
    artifact_path = "rf_model",
    model_name    = "supervised",         # → registrado como "cnds-supervised"
    metrics       = {                     # métricas opcionales del entrenamiento
        "accuracy": ...,              # valores de tu entrenamiento
        "f1_weighted": ...,
    }
)

# LSTM Autoencoder (PyTorch)
log_pytorch_model(
    model         = lstm_model,
    artifact_path = "lstm_autoencoder",
    model_name    = "lstm",
    metrics       = {
        "threshold": ...,             # valores de tu entrenamiento
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
5. Transicionar a "Production". CNDS cargará el nuevo modelo en el próximo restart (los motores RF, IF y LSTM solo consultan MLflow al arrancar).
6. Archivar la versión anterior.

---

## 10. Procedimientos de Entrenamiento

### 10.1 Random Forest — Entrenamiento inicial

**Script:** `scripts/train_rf.py`

**Paso 1: Obtener el dataset**

El script espera la redistribución CIC de UNSW-NB15 en un directorio con dos ficheros: `Data.csv` (las 76 columnas de CICFlowMeter, en el mismo orden que `FLOW_FEATURE_NAMES`) y `Label.csv` (columna `Label` con enteros 0-9, que el script traduce a `Benign`, `Analysis`, `Backdoor`, `DoS`, `Exploits`, `Fuzzers`, `Generic`, `Reconnaissance`, `Shellcode`, `Worms`). Las columnas se toman por posición, no por nombre.

**Paso 2: Entrenar**

```bash
# SMOTE necesita imbalanced-learn, que no está en requirements.txt
pip install imbalanced-learn        # o usar --no-smote

python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15
```

`--data-dir` es obligatorio. Si se pide SMOTE y `imbalanced-learn` no está instalado, el script termina con un mensaje que nombra el paquete y `--no-smote`.

El script recorta negativos a 0, aplica `log1p` a los features con |asimetría| > 5, escala con `StandardScaler`, sobremuestrea con SMOTE las clases minoritarias (solo en train) y entrena un `RandomForestClassifier(class_weight="balanced")`. Guarda el `Pipeline` completo en `<output-dir>/rf_model.joblib`, de modo que `SupervisedEngine` no necesita un scaler aparte. Si `MLFLOW_TRACKING_URI` (o `--mlflow-uri`) está definido, también registra el run en MLflow.

| Opción | Default | Descripción |
|---|---|---|
| `--data-dir` | (obligatorio) | Directorio con `Data.csv` y `Label.csv` |
| `--output-dir` | `models` | Dónde se escribe `rf_model.joblib` (sobrescribe el existente) |
| `--estimators` | 200 | Árboles |
| `--max-depth` | 20 | Profundidad máxima (`None` = sin límite) |
| `--test-size` | 0.20 | Fracción de test |
| `--jobs` | -1 | Núcleos |
| `--no-smote` | — | Omitir el sobremuestreo |
| `--lite` | — | Modelo incluido en el repo: muestra estratificada de 50k filas, 25 árboles, profundidad 10, sin SMOTE; escribe `rf_lite_model.joblib` |

**Paso 3 (opcional): Modelo extendido con payload (86 features)**

```bash
python scripts/retrain_with_payload.py \
    --dataset combined_with_payload.csv \
    --output models/rf_model_v2.joblib \
    --n-estimators 200
```

A diferencia de `train_rf.py`, este script selecciona las columnas **por nombre**: el CSV debe tener las 76 columnas llamadas como `FLOW_FEATURE_NAMES` (snake_case, no los nombres originales de CICFlowMeter) y una columna `Label` con texto. Las 10 columnas de payload que falten se rellenan con ceros. El pipeline es solo `StandardScaler` + Random Forest (sin recorte, `log1p` ni SMOTE). Defaults: `--n-estimators 100`, `--test-size 0.2`, `--random-state 42`.

---

### 10.2 Isolation Forest — Entrenamiento inicial

El repositorio no incluye un script que entrene el IF estático a partir de tráfico real. `scripts/generate_demo_models.py` genera uno con datos sintéticos (50 árboles, `contamination=0.05`) solo para demos. La vía soportada para aprender el tráfico normal de una red es el pipeline baseline en vivo (`src/unsupervised/`, ver [unsupervised.md](unsupervised.md)), que entrena su propio IF + LSTM sin intervención. Los pasos siguientes son un procedimiento manual orientativo para producir `isolation_forest.joblib` e `if_scaler.joblib`.

**Paso 1: Capturar baseline**

```bash
# Capturar tráfico normal (30–60 minutos mínimo)
sudo tcpdump -i eth0 -w baseline_normal.pcap -G 3600 -W 1
```

**Paso 2: Extraer host features del baseline**

```python
# Boceto: no hay un script equivalente en el repo. En ejecución el vector de host
# se calcula al expirar cada flujo; aquí se muestrea cada 50 paquetes.
import numpy as np
from scapy.all import PcapReader
from src.features.host_extractor import HostExtractor

extractor = HostExtractor()
vectors = []
with PcapReader("baseline_normal.pcap") as pcap:
    for i, pkt in enumerate(pcap):
        ts = float(pkt.time)
        ip = extractor.process_packet(pkt, ts)
        if ip and i % 50 == 0:
            vec = extractor.extract_features(ip, now=ts)   # None con menos de 3 paquetes
            if vec is not None:
                vectors.append(vec)

X_baseline = np.array(vectors, dtype=np.float32)  # shape (N, 18)
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
print(f"Offset de decisión: {model.offset_:.4f}")
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

La clase vive en `src/engines/lstm_model.py`; para entrenar basta `from src.engines.lstm_model import LSTMAutoencoder`. Se reproduce aquí como referencia:

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
from src.engines.lstm_model import LSTMAutoencoder

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
        best_val_errors = val_errors
        # El motor carga con load_state_dict(weights_only=True): guardar solo los pesos
        torch.save(model.state_dict(), 'models/lstm_autoencoder.pt')

    if (epoch + 1) % 10 == 0:
        print(f"Epoch {epoch+1}/{EPOCHS} — val_mse={val_mse:.6f}")

# Calcular threshold: percentil 99 del error de reconstrucción en validación (mejor época)
threshold = float(np.percentile(best_val_errors, 99))
print(f"Reconstruction threshold (p99): {threshold:.6f}")

# Guardar config
config = {
    "sequence_length": 20,
    "hidden_dim":      HIDDEN_DIM,
    "latent_dim":      LATENT_DIM,
    "num_layers":      NUM_LAYERS,
    "dropout":         DROPOUT,
    "n_features":      18,
    "reconstruction_threshold": threshold,   # el motor solo lee esta clave
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
# Opción A: 76 features. train_rf.py siempre escribe rf_model.joblib dentro de
# --output-dir, así que usar un directorio aparte para no pisar el modelo activo
python scripts/train_rf.py --data-dir /path/to/CIC-UNSW-NB15 --output-dir models_new

# Opción B: 86 features con payload
python scripts/retrain_with_payload.py \
    --dataset combined_with_payload.csv \
    --output models/rf_model_v2.joblib \
    --n-estimators 200 \
    --test-size 0.2

# Validar el nuevo modelo antes de reemplazar el existente
python scripts/pcap_replay.py test_attacks.pcap --attacks attacks.csv --report report.md   # el modelo se toma de models/ (ver wiki/Evaluation.md)

# Si la validación es satisfactoria, activar:
# En .env: RF_MODEL_FILE=rf_model_v2.joblib   (nombre relativo a MODELS_DIR, por defecto models/)
# Reiniciar CNDS
```

El orden de carga del motor supervisado es: FT-Transformer si su checkpoint está disponible; si no, el Random Forest de MLflow (`cnds-supervised`, stage Production), luego `RF_MODEL_FILE` y por último `rf_lite_model.joblib`. Un fichero local nuevo no tiene efecto mientras exista una fuente anterior en esa lista.

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

# score = min(error / reconstruction_threshold, 1.0)
# Subir threshold → scores más bajos, menos FPs (más permisivo)
# Bajar threshold → scores más altos, menos FNs (más agresivo)
config['reconstruction_threshold'] = 3.5  # ajustar según observación

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
    metrics       = {'f1_weighted': ..., 'test_samples': ...}   # valores de tu entrenamiento
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

`EvalResult` guarda una predicción por flujo (`true_label`, `is_anomaly`, `ensemble_score`, ...) y deriva de ellas los contadores y las métricas:

```python
@dataclass
class EvalResult:
    predictions: List[dict]

    # tp / fp / tn / fn: propiedades calculadas sobre predictions
    # (ataque = true_label distinto de BENIGN; acierto = is_anomaly)

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
python scripts/pcap_replay.py test_attacks.pcap \
    --output results.json --report report.md \
    --labels labels.csv          # src_ip,dst_ip,src_port,dst_port,protocol,label
# o --attacks attacks.csv (label,src_ip,dst_ip,dst_port,start,end); ver wiki/Evaluation.md
```

### Evaluación con el digital twin

```bash
cd demo
python run_demo.py            # opciones: --no-generate, --scenario NAME
```

La salida es solo por terminal (no hay opción de JSON): las alertas de cada escenario, una tabla resumen con el número de alertas por escenario, el desglose por severidad y las técnicas MITRE observadas.

### Benchmark de rendimiento mínimo recomendado

| Escenario | Detection rate mínima | FP rate máxima |
|---|---|---|
| ICMP Flood | 99% | < 1% |
| SYN flood/scan sobre un mismo flujo (>20 SYNs, `PORT_SCAN_THRESHOLD`) | 95% | < 2% |
| Brute Force SSH/FTP | 85% | < 5% |
| Web SQLi/XSS | 90% | < 3% |
| Data Exfiltration (lenta) | 70% | < 5% |
| Tráfico normal | — | < 2% |

Estos valores son objetivos recomendados, no resultados medidos. Si un modelo recién entrenado no los alcanza en `pcap_replay.py`, no debería promoverse a producción. Dos de las filas no son alcanzables hoy: un barrido de puertos tipo `nmap -sS` genera un flujo por puerto y la regla `syn_scan` (que cuenta SYNs dentro de un mismo flujo) no dispara (issue #87), y no existe una regla para fuerza bruta SSH/FTP (issue #88). Ver [use-cases.md](use-cases.md).

---

## 13. Referencia de Hiperparámetros

Todos los parámetros configurables vía `.env`, con sus valores por defecto y sus efectos:

### Parámetros del FT-Transformer

| Variable | Default | Rango | Descripción |
|---|---|---|---|
| `FT_TEMPERATURE` | 2.0 | [0.1, 10.0] | Temperature scaling sobre logits antes de softmax. T > 1 reduce over-confidence; T = 1.0 desactiva. |
| `FT_SCORE_THRESHOLD` | 0.50 | [0, 1] | Umbral de `anomaly_score()` (1 − P(Benign)). Sin efecto hoy: ningún camino en ejecución llama a ese método |
| `FT_USE_GPU` | false | — | Inferencia en CUDA con autocast bfloat16 si `true` |

**Nota sobre dependencias Python:** `scikit-learn` está pinado a `>=1.6.1,<2.0` para proteger la compatibilidad del `StandardScaler` serializado en `unified_scaler.pkl`. Una actualización a scikit-learn 2.0+ puede invalidar el scaler existente — si se actualiza la dependencia, regenerar el scaler con el mismo conjunto de entrenamiento.

---

### Parámetros del Ensemble

| Variable | Default | Rango | Efecto al aumentar |
|---|---|---|---|
| `WEIGHT_SUPERVISED` | 0.30 | [0, 1] | Más peso al motor supervisado (FT-T o RF fallback) |
| `WEIGHT_IFOREST` | 0.20 | [0, 1] | Más sensible a anomalías volumétricas |
| `WEIGHT_LSTM` | 0.10 | [0, 1] | Más sensible a comportamiento temporal |
| `WEIGHT_RULES` | 0.25 | [0, 1] | Más sensible a patrones de umbral |
| `WEIGHT_BASELINE` | 0.15 | [0, 1] | Peso del motor baseline (unsupervised pipeline en vivo) |
| `ENSEMBLE_THRESHOLD` | 0.55 | [0, 1] | Bajar → más FPs, más detección; Subir → menos FPs, más FNs |
| `CALIBRATION_TEMPERATURE` | 1.0 | (0, 10] | Bajar → sharper scores; Subir → softer scores (ensemble) |

### Parámetros del Random Forest

No son variables de entorno: se fijan al entrenar.

| Parámetro | Default | Descripción |
|---|---|---|
| `n_estimators` | 200 (`train_rf.py --estimators`), 100 (`retrain_with_payload.py --n-estimators`) | Árboles |
| `max_depth` | 20 (`train_rf.py --max-depth`); sin límite en `retrain_with_payload.py` | Profundidad máxima |
| `random_state` | 42 | Semilla de reproducibilidad |
| `test_size` | 0.2 | Fracción de test (`--test-size`) |

### Parámetros del Isolation Forest

| Parámetro | Valor | Descripción |
|---|---|---|
| `contamination` | 0.01 | Valor que usa el pipeline baseline en vivo (`window_trainer.py`, 200 árboles) y el ejemplo de la sección 10.2 |
| Sigmoid steepness | 5.0 | Hardcoded en `isolation_forest.py:score()` |

`IF_CONTAMINATION` (0.05), `IF_N_ESTIMATORS` (200), `IF_MIN_SAMPLES` e `IF_TRAINING_STATUS_FILE` están definidos en `src/config.py`, pero ningún código en ejecución los lee.

### Parámetros del LSTM

| Clave en lstm_config.json | Valor actual | Descripción |
|---|---|---|
| `sequence_length` | 20 | Pasos temporales por secuencia |
| `hidden_dim` | 64 | Dimensión del estado oculto LSTM |
| `latent_dim` | 32 | Dimensión de la representación latente |
| `num_layers` | 2 | Capas LSTM apiladas |
| `dropout` | 0.2 | Dropout entre capas LSTM |
| `n_features` | 18 | Host features por paso |
| `reconstruction_threshold` | 2.973 | Error de reconstrucción (MSE) que se normaliza a score 1.0; 0.1 si la clave falta |

### Parámetros de Extracción

| Variable | Default | Efecto |
|---|---|---|
| `FLOW_TIMEOUT` | 120s | Más largo → features más completos; más memoria |
| `ACTIVE_IDLE_THRESH` | 1.0s | Gap que separa períodos activos/inactivos |
| `MIN_PACKETS_FOR_ML` | 10 | Sin efecto: definido en `src/config.py`, ningún código en ejecución lo lee |
| `HOST_WINDOW_SIZE` | 100 | Más grande → estadísticas más estables |
| `MAX_TRACKED_IPS` | 5,000 | Más grande → más estado en memoria |
| `MAX_ACTIVE_FLOWS` | 50,000 | Límite de flujos concurrentes |

### Umbrales de Reglas

| Variable | Default | Notas |
|---|---|---|
| `ICMP_FLOOD_THRESHOLD` | 50 | `icmp_flood`: paquetes forward de un flujo ICMP por encima de este valor |
| `PORT_SCAN_THRESHOLD` | 20 | `syn_scan`: SYNs en un mismo flujo por encima de este valor y menos de 5 paquetes forward con datos |
| `LARGE_PAYLOAD_BYTES` | 10,000 | `large_payload`: tamaño del mayor paquete forward del flujo |
| Ratio asimétrico | 50 | Hardcoded en `rules.py`: bytes forward / bytes backward, con más de 10 paquetes forward y al menos uno backward |

### Parámetros de Pesos Adaptativos

| Variable | Default | Descripción |
|---|---|---|
| `ADAPTIVE_WEIGHTS_ENABLED` | `false` | Activar mecanismo de adaptación |
| `ADAPTIVE_MIN_SAMPLES` | 100 | Alertas etiquetadas mínimas |
