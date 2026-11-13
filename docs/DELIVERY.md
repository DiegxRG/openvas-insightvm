# Entrega persistente y antiduplicados

## Ubicación y flujo

La capa está entre el JSON preparado y el POST. No altera el colector, el filtro
GMP, las ocurrencias ni los 13 campos del contrato MiFibra. El JSON preparado
sigue conteniendo todas las alarmas para revisión; omitir entregas ya confirmadas
no significa borrarlas del archivo.

1. Recolectar y preparar el snapshot completo.
2. En una transacción SQLite, registrar las nuevas versiones en una outbox.
3. Leer pendientes vencidos en lotes de 200, hasta terminar todos los disponibles.
   El lote pagina la base; no limita el total enviado por corrida.
4. Enviar cada JSON original fuera de la transacción.
5. Confirmar solo con HTTP 2xx y `success=true`. Persistir la confirmación antes
   de continuar. Un reinicio conserva tanto confirmaciones como pendientes.
6. Un fallo aplica backoff y mantiene la versión. Las versiones de un finding
   conservan orden FIFO; no se permite que un reintento antiguo sobrescriba un
   cambio más reciente. Si el colector falla, el scheduler igual drena pendientes.

## Identidad y cambios

El namespace separa destino backend, Local, servidor/usuario GMP, tareas y
severidades configuradas. No contiene credenciales. Dentro de él, finding_id
identifica equipo/NVT. Cambiar el namespace crea un historial independiente y
puede requerir reenviar; mantener una configuración coherente por instalación.

La huella semántica considera todos los campos enviados excepto fechaalarma,
normaliza orden y formato de CVEs, y añade puertos, severidades, CVSS y CVEs de
las ocurrencias como contexto local. Una fecha de observación, UUID de reporte
o UUID de resultado nuevos por sí solos no provocan reenvío. Cambios técnicos,
altas nuevas, aumentos o disminuciones de CVSS, CVEs agregados o retirados,
hostname/título y puertos nuevos sí generan una versión pendiente. La huella y
el contexto nunca se añaden al POST.

Cada evento conserva también el snapshot completo del finding como contexto
local, incluidas sus ocurrencias. Así los detalles de cambios pendientes no
dependen de que filtered_latest.json todavía contenga una versión anterior.

Se conservan también transiciones A → B → A: no se deduplica contra cualquier
versión histórica, sino contra la última versión observada del finding.

Solo una captura completa sin diagnósticos ni errores de validación puede
marcar una identidad ausente localmente. Si reaparece, se crea una nueva
generación y se envía aunque su contenido coincida. Eso no envía cierres al
backend: el contrato actual no los define. Capturas parciales no infieren
desapariciones. Marcas de inicio por snapshot y finding impiden que una captura
más antigua revierta una observación nueva en procesos concurrentes.

## Almacenamiento y concurrencia

SQLite estándar de Python, WAL, synchronous=FULL, índices por scope/estado y por
finding. Transacciones cortas, sin HTTP dentro de ellas. Un lock del sistema
operativo permite un solo emisor por namespace; se libera si el proceso muere.
Un segundo emisor informa error y no hace un envío paralelo ni un fallback sin
estado. Una base corrupta/inaccesible también detiene la entrega, sin borrar ni
reinicializar silenciosamente el estado.

Esta estructura está pensada para un servidor con almacenamiento local. SQLite
WAL [requiere el mismo host y no es apropiado para un filesystem de red](https://sqlite.org/wal.html).
Para varios nodos emisores se necesitaría estado/cola compartidos y coordinación
distribuida. No colocar esta base en NFS ni copiar una base distinta por proceso.

Solo se purga el historial de eventos confirmados de más de 90 días. Se
conservan los checkpoints de identidad para que no reaparezcan duplicados por
purga y nunca se eliminan pendientes automáticamente. Respaldar con la API
backup de SQLite, o con el agente parado incluyendo los archivos WAL asociados;
no copiar únicamente un .sqlite3 abierto y asumir que contiene todo.

## Confirmaciones y límites del backend

Un conflicto `Ya existe un registro activo` NO confirma que el backend guardó
esa versión ni sus cambios. Permanece pendiente y aparece como conflicto; no se
descarta. Un backend de solo inserción que rechace actualizaciones necesita
soportar actualización/upsert por finding_id para aceptar cambios. Esta capa
no inventa endpoints ni transforma el JSON para ocultar ese problema.

La semántica es al menos una vez ante fallos ambiguos. HTTP y SQLite no pueden
confirmarse como una sola transacción: si el backend guardó pero el proceso cae
antes de registrar el ACK, se reintenta. Evitar también ese duplicado requiere
idempotencia/unicidad del backend. En las corridas normales confirmadas no se
realizan POST repetidos.

## Configuración y operación

```dotenv
BACKEND_ENABLED=false
DELIVERY_DEDUP_ENABLED=true
DELIVERY_STATE_PATH=runtime/openvas/delivery.sqlite3
DELIVERY_BATCH_SIZE=200
DELIVERY_RETRY_SECONDS=60
DELIVERY_RETRY_MAX_SECONDS=3600
DELIVERY_ACK_RETENTION_DAYS=90
```

El backend deshabilitado y el comparador de metadata no crean ni confirman
estado de entrega. Los JSON descargados no se importan como si ya estuvieran
enviados. La primera activación real registra/envía todas las alarmas actuales.
Las pruebas usan bases separadas y un backend ficticio, nunca la base productiva.

La base y sus archivos auxiliares están excluidos de Git. No borrarlos al hacer
git pull ni al desplegar: perder la base provoca reenvíos. El .env se conserva;
las nuevas opciones tienen valores predeterminados y no requieren nuevos pip.

```bash
# Estadísticas: no necesita conectarse a GMP ni al backend.
python tools/delivery_state.py stats
# Adelantar el siguiente reintento de un finding pendiente específico:
python tools/delivery_state.py retry --scope HASH --finding-id ID
# Forzar que la próxima observación se considere reaparición:
python tools/delivery_state.py resend-next-observation --scope HASH --finding-id ID
```

Los hashes de scope salen en stats. Estos comandos no hacen POST. El último es
útil, por ejemplo, tras un cierre manual en backend que el colector no conoce.
Los errores de envío y pending_total aparecen en run_latest.meta.json. Con
pendientes, main.py --once devuelve código 1 aunque la recolección haya sido
correcta. No requiere esperar dormido dentro de una petición para reintentar.

## Prueba controlada con JSON guardado

```bash
python tools/test_delivery_controlled.py \
  --prepared validation/CAPTURA/openvas_prepared_backend.json \
  --findings validation/CAPTURA/openvas_filtered.json \
  --output validation/PRUEBA_NUEVA
```

El directorio de salida debe ser nuevo. El transporte es un stub en memoria a
un destino .invalid; no se llama al backend real ni a GMP. Comprueba primera
entrega, replay con nuevo cliente sobre la misma SQLite, crítica nueva, cambios
de CVEs/título/puerto, repetición de cambios y reaparición. La suite pytest añade
timeouts, conflictos, orden de versiones, rollback, corrupción, concurrencia,
muerte de proceso y drenaje cuando falla el colector.
