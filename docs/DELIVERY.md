# Entrega de snapshots completos con SQLite

## Contrato y comportamiento

Se sigue el envoltorio del cliente INSIGHT del servidor, revisado en el commit
`02cb850`: un POST JSON con exactamente `snapshot_id` y `alarms`. Cada elemento
mantiene los 13 campos documentados en README; `cves` es una lista JSON. No se
agregan columnas de SQLite al POST. `source=openvas` y `TipoAlarma` identifica
OpenVAS mediante BACKEND_ALARM_TYPE. La referencia y sus límites están en
[REMOTE_INSIGHT_CONTRACT.md](REMOTE_INSIGHT_CONTRACT.md).

| Observación completa | POST |
|---|---|
| Primera captura: 100 alarmas | 1 snapshot con 100 |
| Mismo contenido | Ninguno |
| 5 nuevas, total 105 | 1 snapshot con las 105 |
| Cambia CVSS o CVEs de 5 de las 100 | 1 snapshot con las 100 |
| Quedan 70 de las 100 | 1 snapshot con las 70 |
| Captura completa sin hallazgos | 1 snapshot con alarms=[] |
| Misma captura vacía otra vez | Ninguno |
| Consulta fallida, parcial o con errores de validación | No encolar esa captura; reintentar pendientes anteriores |

No se envían diferencias por alarma. Tampoco se inventa una llamada de cierre:
el receptor debe interpretar los snapshots según su contrato. Un snapshot vacío
no es una notificación de “sin cambios”. La identidad del origen en snapshots
vacíos y la reconciliación/cierre del receptor siguen pendientes de revisar en
PHP; no se afirma que una ausencia cierre automáticamente una alarma.

## Comparación de contenido

Se compara una huella del conjunto completo, ordenado por finding_id. Incluye
los campos de cada alarma salvo fechaalarma; detecta altas, bajas, severidad,
CVSS, CVEs, hostname, IP, título y demás cambios de contenido. CVEs se normalizan
como conjunto ordenado y CVSS como número. Cuando se aportan los hallazgos del
colector, también se comparan puerto, severidad, CVSS y CVEs de las ocurrencias.
Cambiar solo fecha de observación, UUID de reporte/resultado u orden de listas
no produce otra entrega. Las ocurrencias completas se conservan localmente;
el contrato de 13 campos sigue agrupando por activo y NVT.

Un finding_id repetido en una misma captura se rechaza como ambiguo. Una captura
anterior a la última observada no revierte el checkpoint. El scheduler comprueba
que no haya diagnósticos del colector ni errores de preparación antes de
considerar completa la captura. No se alteran el filtro GMP ni la paginación.

## Persistencia, orden y reintentos

SQLite usa WAL y synchronous=FULL. Una transacción guarda el snapshot completo,
su contexto de hallazgos y el nuevo checkpoint de contenido. Se compara contra
la última observación encolada, incluso si todavía está pendiente: una secuencia
A → B → A conserva los tres snapshots en orden.

Un bloqueo del sistema operativo admite un solo emisor por ámbito y se libera
si muere el proceso. El ámbito incluye receptor, Local, servidor/usuario GMP,
tareas y severidades, sin contraseñas. SQLite está destinado a un único servidor;
no se debe compartir su archivo mediante NFS ni ejecutar réplicas con bases
independientes para el mismo ámbito.

Cada snapshot usa ISO 8601 UTC con resolución de segundos, por ejemplo
2026-11-13T20:10:00Z. El endpoint real rechazó los UUID en una prueba manual.
SQLite conserva un reloj lógico por ámbito: si varias observaciones caen en
el mismo segundo, asigna el siguiente segundo disponible. El reloj sobrevive
la eliminación del historial confirmado; no se reutilizan IDs por esa poda.
El ID identifica la captura, no sustituye fechaalarma de cada hallazgo.
El ID y JSON se guardan antes del POST y son inmutables en todos los reintentos.
Se exige HTTP 2xx y success=true para confirmar, o una respuesta de repetición estrictamente verificada. Conflictos, errores HTTP,
timeouts y respuestas inválidas mantienen el snapshot pendiente con backoff
exponencial (60 segundos a 3600 por defecto).

La cola es FIFO por ámbito completo. Si falla el primero, ninguno posterior
puede adelantarlo. Cada POST incluye todo el snapshot, sin dividir sus alarmas
en lotes. DELIVERY_BATCH_SIZE se conserva por compatibilidad de configuración;
no recorta el contenido ni permite adelantar snapshots.

Solo se elimina historial confirmado después de DELIVERY_ACK_RETENTION_DAYS
(90 por defecto); pendientes y checkpoint no expiran. Un timeout después de que
el receptor haya guardado datos puede provocar reenvío: HTTP y SQLite no tienen
una transacción compartida. La idempotencia final depende de que el backend use
el mismo snapshot_id y su llave compuesta; no se promete entrega exactamente una
vez sin cooperación del receptor.

BACKEND_ENABLED=false impide POST y no crea ni cambia la base. Con
DELIVERY_DEDUP_ENABLED=false se conserva SQLite y FIFO, pero cada observación
completa encola un snapshot aunque el contenido sea igual. No hay fallback de
POST individual si SQLite falla.

Los contadores attempted, snapshots_sent y pending_total cuentan snapshots;
sent_ok suma las alarmas de los snapshots confirmados (puede ser 0 al confirmar
un snapshot vacío). Un ciclo parcial se marca con backend_errors aunque pueda
drenar pendientes correctamente.

## Actualización desde la cola anterior

Se mantiene DELIVERY_STATE_PATH=runtime/openvas/delivery.sqlite3. El esquema 3
conserva snapshot_events y snapshot_checkpoints, y agrega snapshot_clocks. Las tablas de la versión 1 se
conservan para auditoría. Si solo hay eventos antiguos confirmados, la migración
es automática y la siguiente captura completa establece el primer snapshot.

Si hay eventos individuales pendientes de la versión 1, la migración se bloquea
sin enviarlos, borrarlos ni marcarlos confirmados. Esos registros no permiten
reconstruir por sí solos un snapshot histórico completo. Conservar la base y sus
archivos WAL/SHM y reconciliar esas entregas con el receptor antes de cambiar de
modo. No borrar el archivo ni editar estados a ciegas para eludir el bloqueo.
Una base corrupta o de versión desconocida también bloquea los POST.

## Inspección y controles locales

```bash
python tools/delivery_state.py --db runtime/openvas/delivery.sqlite3 stats
python tools/delivery_state.py --db runtime/openvas/delivery.sqlite3 retry --scope SCOPE
python tools/delivery_state.py --db runtime/openvas/delivery.sqlite3 retry --scope SCOPE --snapshot-id ID
python tools/delivery_state.py --db runtime/openvas/delivery.sqlite3 force-next-snapshot --scope SCOPE
```

Estos comandos no conectan a GMP ni al backend. retry adelanta la fecha de
reintento, sin cambiar ID/payload ni saltarse FIFO. force-next-snapshot marca el
checkpoint para volver a encolar la próxima captura completa con otro ID.
BACKEND_ENABLED sigue controlando cualquier envío posterior.

## Artefactos y prueba controlada

main.py guarda el envoltorio listo en
runtime/openvas/artifacts/snapshot_request_latest.json. prepared_backend_latest.json
incluye request_payload y metadatos de preparación. Si la corrida no se envía,
el ID del artefacto es una propuesta, no una confirmación del receptor.
compare_metadata.py guarda openvas_snapshot_request.json y nunca hace POST.

Para probar los JSON guardados sin consultar GMP ni usar HTTP real:

```bash
python -m pytest -q
python tools/test_delivery_controlled.py \
  --prepared /ruta/openvas_prepared_backend.json \
  --findings /ruta/openvas_filtered.json \
  --output validation/snapshot_test_nuevo
```

La prueba regenera el contrato desde todos los hallazgos, usa una base aislada,
sustituye session.post por un receptor en memoria y escribe summary.json y
openvas_snapshot_request.json en la carpeta nueva. Nunca usar la base de prueba
como estado productivo. Resultados de esta entrega en
[validation/2026-11-13-snapshots/README.md](validation/2026-11-13-snapshots/README.md).

El esquema 2 migra al 3 conservando el historial. Si conserva snapshots UUID
pendientes, la migración se bloquea sin cambiarlos ni enviarlos: el receptor
real no acepta ese formato y cambiar un ID pendiente sin reconciliarlo podría
romper la idempotencia. Las bases de pruebas anteriores no son estado productivo.

## Copias y retención

No se descarga automáticamente ningún archivo a la laptop al enviar. En el
servidor, los archivos *_latest.json se sobrescriben en cada corrida, no se
crea una carpeta por POST. PERSIST_RAW_API_DEBUG=false evita XML históricos
adicionales. SQLite sí guarda snapshots pendientes completos para reintentos,
y conserva historial confirmado durante DELIVERY_ACK_RETENTION_DAYS (90 días
por defecto). La poda elimina ese historial confirmado; no borra pendientes
ni el checkpoint/reloj. Los directorios validation/ se crean explícitamente
para pruebas manuales y sus evidencias; no los crea el envío normal.

## Respuesta del receptor al repetir un snapshot

La prueba real aceptó 1.258 alarmas. Al repetir exactamente el mismo JSON y ID,
el receptor respondió HTTP 200, success=false y un error por cada llave ya
existente (finding_id,snapshot_id). El emisor reconoce ese caso como confirmación
de reintento únicamente si los 1.258 errores cubren exactamente los IDs enviados,
sin repetidos ni faltantes, con el mismo snapshot_id, total y texto de llave
duplicada esperado. No interpreta cualquier conflicto/error como entrega exitosa.
La respuesta original success=false se conserva; se añade la marca local
idempotent_replay_confirmed y el contador replayed_snapshots. Esto permite cerrar
la cola si el receptor guardó todo y se perdió el primer ACK. Un resultado parcial,
error distinto, snapshot ajeno o HTTP no 2xx permanece pendiente.

BACKEND_TIMEOUT pasa a 180 segundos: la inserción real tardó 35,373 segundos y
superó el valor anterior de 30. BACKEND_CA_BUNDLE permite indicar un PEM de confianza
para el certificado privado/autofirmado sin deshabilitar la verificación TLS.
El certificado observado vence el 30 de marzo de 2027; su autenticidad inicial
se basó en la conexión al endpoint interno autorizado, no en una CA pública.
