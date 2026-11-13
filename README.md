# OpenVAS / MiFibra — integración compatible con INSIGHT

Agente Python que consulta reportes existentes de OpenVAS/Greenbone mediante GMP y transforma sus resultados al mismo contrato JSON de alarmas de INSIGHT-MIFIBRA. Descarga metadata, filtra vulnerabilidades altas y críticas y prepara el JSON para MiFibra/Txdxsecure. El envío al backend es opcional y está deshabilitado por defecto.

La [capa de entrega persistente y antiduplicados](docs/DELIVERY.md) utiliza SQLite para conservar snapshots completos, detectar cambios de contenido y reintentar con el mismo ID. El POST contiene snapshot_id y alarms; cada alarma mantiene 13 campos y cves es una lista.

Solo consulta datos existentes; no inicia escaneos. El comando de comparación nunca envía alarmas, incluso si el archivo de configuración habilita el backend.

## 1. Requisitos de Linux

- Python 3.10 o superior, Git, pip y soporte para venv.
- Acceso desde el servidor a GMP: configuración prevista `10.208.232.43:41000` por TCP plano.
- Usuario y contraseña GMP con acceso a las tareas/reportes.
- Acceso a GitHub y al índice de paquetes. Para un repositorio privado, usar la autenticación GitHub configurada en el servidor.

En Debian/Ubuntu, si faltan herramientas:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-pip python3-venv
python3 --version
```

## 2. Primera instalación

Ejecutar como el usuario que operará el agente:

```bash
git clone --branch main https://github.com/DiegxRG/openvas-insightvm.git
cd openvas-insightvm
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
nano .env
```

El clone ya descarga la versión de main disponible en ese momento. No requiere un pull adicional inmediatamente después.

Completar en .env al menos:

```dotenv
GVM_TRANSPORT=plain
GVM_ALLOW_PLAIN_TCP=true
GVM_HOST=10.208.232.43
GVM_PORT=41000
GVM_USERNAME=your-user
GVM_PASSWORD='your-password'
ALERT_SEVERITIES=critical,high
BACKEND_ENABLED=false
```

Las comillas simples conservan caracteres como $ y & de la contraseña. Python carga el archivo directamente: no ejecutar `source .env`. La API key del proyecto anterior AWS/S3 no se utiliza en este backend. El .env se configura por separado en cada servidor y está excluido de Git.

## 3. Prueba real de metadata, sin enviar al backend

Desde la raíz del repositorio, con el entorno virtual activado:

```bash
python tools/compare_metadata.py --live --output validation/metadata_live
```

Este comando consulta GMP, descarga XML, extrae altas y críticas, genera el JSON final y compara sus campos y tipos con un ejemplo de INSIGHT incluido en el repositorio. No requiere clonar INSIGHT-MIFIBRA. No realiza POST al backend.

Si la captura termina, se generan:

| Archivo dentro de validation/metadata_live/ | Contenido |
|---|---|
| openvas_prepared_backend.json | Preparación completa; request_payload contiene el snapshot que se enviaría |
| openvas_filtered.json | Hallazgos normalizados y ocurrencias por puerto/tarea |
| comparison.json | Resultado de validación, campos y tipos |
| capture_metrics.json | Tamaños por página/reporte, archivos combinados y error de captura si ocurre |
| insight_reference_alarm.json | Ejemplo de contrato INSIGHT utilizado |
| captured_xml/tasks.xml | XML de tareas consultadas |
| captured_xml/report_0000.xml | XML del primer reporte; puede haber más archivos numerados |

Para ver el JSON:

```bash
python -m json.tool validation/metadata_live/openvas_prepared_backend.json
cat validation/metadata_live/comparison.json
```

Se espera `passed: true` cuando existen alarmas elegibles y cumplen el contrato. `comparison_status: no_eligible_findings` indica que no hubo alarmas que comparar; revisar diagnósticos, severidades y reportes completados. No equivale por sí solo a falta de conectividad. Código de salida 1 significa captura fallida o comparación no aprobada. Una ejecución fallida puede dejar archivos anteriores: comprobar sus fechas y la salida del comando.

## 4. Actualizar posteriormente

Cuando existan cambios nuevos en GitHub:

```bash
cd /ruta/donde/clonaron/openvas-insightvm
git switch main
git pull --ff-only origin main
source .venv/bin/activate
python -m pip install -r requirements.txt
python tools/compare_metadata.py --live --output validation/metadata_live
```

Sustituir la ruta por la ubicación real. El .env local se conserva porque no se versiona. Revisar .env.example por si aparecen variables nuevas. Si pull informa cambios locales o divergencias, revisar antes de continuar. Reiniciar cualquier agente en ejecución para que cargue el código actualizado.

## 5. Ejecutar el agente

Un ciclo de recolección y preparación:

```bash
python main.py --once
```

Con `BACKEND_ENABLED=false`, guarda el JSON sin enviar alarmas. Los archivos quedan en OPENVAS_ARTIFACTS_DIR, por defecto:

```text
runtime/openvas/artifacts/filtered_latest.json
runtime/openvas/artifacts/prepared_backend_latest.json
runtime/openvas/artifacts/run_latest.meta.json
```

Para repetir ciclos cada 600 segundos en primer plano:

```bash
python main.py
```

Se detiene con Ctrl+C; cerrar la terminal puede detenerlo. Esta guía cubre instalación y pruebas manuales. La operación permanente requiere configurar un supervisor como systemd.

Después de validar los datos, `BACKEND_ENABLED=true` habilita un POST de snapshot completo al BACKEND_URL cuando cambia el contenido. El comando compare_metadata continúa sin enviar alarmas. main.py --once devuelve código 1 si falla la captura o hay errores de envío/validación. Logs: logs/integration.log.

## 6. Qué obtiene y qué envía

Extrae IP, hostname cuando existe, OID del NVT, título, severidad numérica/CVSS, CVEs y fecha operativa. La evidencia local conserva también tarea, reporte y puerto. Solo acepta altas (7.0 <= CVSS < 9.0) y críticas (9.0 <= CVSS <= 10.0).

El filtro se envía a GMP antes de transferir los resultados: para ambas severidades se solicita `severity>6.9` en el atributo `filter` de `get_reports`, junto con `first`, `rows` y `ignore_pagination=0`. Para High solamente se solicita `severity>6.9 and severity<9.0`; para Critical, `severity>8.9`. Es necesario escribir `and` al combinar límites: GMP combina expresiones por OR de forma predeterminada. No se usa `levels=hmlg`, que descargaba también Medium/Low/Log y filtraba después. Se mantiene la validación local. Si una respuesta GMP contiene severidades fuera de las solicitadas, scores inválidos o más resultados que `rows`, se rechaza la captura en lugar de continuar descargando datos ajenos al filtro. No se hace un segundo intento sin filtro.

`GVM_LEAN_REPORT=true` pide XML reducido conservando los resultados detallados. `GVM_TIMEOUT=120` permite hasta 120 segundos de espera de conexión/inactividad; `GVM_REQUEST_TIMEOUT=600` establece un máximo de 600 segundos por solicitud/página. Este último no es un límite para toda la captura de 47 tareas. Los límites de tamaño permanecen en 30 MiB por respuesta/XML y 64 MiB de tráfico por reporte. Actualizar estas variables también en el .env de instalaciones existentes.

`capture_metrics.json` registra el filtro solicitado, severidades efectivamente recibidas, duración y bytes por página, además de los límites de consulta. Permite distinguir demora de GMP, exceso de metadata y una respuesta que ignore el filtro.

Para obtener todas las altas y críticas se solicita explícitamente `min_qod=0`: se elimina el umbral implícito de calidad de detección (habitualmente 70) del servidor. No hay TOP_N ni límite de número de alarmas. Con `GVM_TASK_IDS` vacío se incluyen todas las tareas visibles para el usuario GMP. Los resultados repetidos por equipo y NVT se consolidan para backend; sus ocurrencias permanecen en `openvas_filtered.json`. El alcance es el último reporte completado por tarea, no todos los reportes históricos.

El backend recibe estas 13 claves, como INSIGHT:

| Campo | Valor/origen |
|---|---|
| finding_id | asset_id + "_" + vulnerability_id |
| servidor | Hostname; IP como respaldo |
| ip | Host afectado |
| TipoAlarma | BACKEND_ALARM_TYPE; etiqueta fija de OpenVAS |
| Local | BACKEND_LOCAL |
| fechaalarma | creation_time del resultado; respaldo scan_end, en UTC |
| asset_id | openvas:IP |
| vulnerability_id | OID del NVT |
| vulnerability_title | Título del resultado/NVT |
| severity | High o Critical |
| cvss_score | Número entre 7.0 y 10.0 |
| cves | Lista JSON de CVEs; [] si no hay |
| source | openvas |

BACKEND_URL predeterminado: `https://10.208.232.208/txdxsecure/guarda_alarma.php`. Se envía un único objeto {"snapshot_id": "ID", "alarms": [...]} con toda la foto actual y Content-Type application/json. El archivo snapshot_request_latest.json contiene ese envoltorio sin metadatos internos. Se espera una respuesta JSON con success; el mensaje "Ya existe un registro activo" se contabiliza como conflicto.

## 7. Reglas y límites

- Se consulta last_report por tarea y se exige scan_run_status=Done en el reporte. No se recorre el historial. Una tarea en ejecución puede tener un reporte anterior completado.
- GVM_TASK_IDS restringe tareas por IDs separados por comas; vacío incluye todas las visibles. Delimitarlo a MiFibra cuando corresponda.
- Se paginan tareas y resultados. Una página repetida o alcanzar GVM_MAX_PAGES hace fallar el ciclo antes de enviar datos parciales.
- No se aplica TOP_N. OPENVAS_REPORT_MAX_KB limita cada respuesta y cada XML combinado/exportado a 30720 KiB (30 MiB) por defecto. OPENVAS_PAGINATION_MAX_KB limita por separado el tráfico acumulado de páginas por listado/reporte (65536 KiB, 64 MiB por defecto). Este tráfico puede ser mayor que el archivo combinado debido a metadata repetida por GMP. Todos los límites son en KiB (1024 bytes). Al actualizar una instalación existente, cambiar estos valores también en su .env local, que Git no modifica.
- Los resultados del mismo equipo y NVT se consolidan. Se conserva el mayor CVSS y, en empate, la fecha más reciente; una observación alta posterior no puede ocultar una crítica anterior. Se unen CVEs y cada ocurrencia conserva reporte, tarea, puerto, resultado, severidad, CVSS, fecha y CVEs en el JSON local. El contrato del backend mantiene sus 13 campos.
- La IP identifica el activo; su reasignación afecta la identidad. No se usa el reporte como identidad del equipo.
- Fechas sin zona se interpretan como UTC. INSIGHT conserva la hora recibida sin convertirla: confirmar con backend la zona horaria esperada.
- Se descartan resultados sin fecha, IP, título, OID o score válido, con diagnóstico.
- Un reporte completado es una observación histórica; no garantiza vigencia actual. No se inventa un estado vulnerable equivalente a INSIGHT.
- La entrega usa una cola SQLite persistente: omite versiones ya confirmadas, conserva cambios y reintenta fallos. Ver la sección de antiduplicados; el colector y el JSON final permanecen completos.
- Se reintentan errores transitorios de conexión GMP. Los errores de envío se registran y los hallazgos se vuelven a presentar en el ciclo siguiente.
- PERSIST_RAW_API_DEBUG=true guarda XML de tareas/reportes dentro de raw_api_FECHA.json al ejecutar main.py. Los logs no imprimen autenticación.

Las variables heredadas OPENVAS_TOP_N, OPENVAS_STATE_PATH, META_MAX_KB, OPENVAS_OUTPUT_MODE, OPENVAS_DETAIL_LEVEL y TXDXAI_API_KEY_OPENVAS no se utilizan en este flujo.

## 8. Diagnóstico de red

TimeoutError significa que no se logró abrir TCP: revisar red/VPN, firewall y servicio GMP en la IP/puerto indicados. Todavía no se validaron credenciales. En Linux, si está instalado netcat:

```bash
nc -vz -w 5 10.208.232.43 41000
```

ConnectionRefusedError indica rechazo de la conexión; revisar puerto y servicio. PermissionError indica un bloqueo local de permisos o política de red. Un rechazo GMP con código de estado ocurre después de abrir TCP y requiere revisar el servicio/permisos/credenciales según el caso.

La captura real guardada del servidor contiene 1.258 grupos altos/críticos. Esta versión se valida con esos hallazgos guardados y receptor simulado; no certifica aceptación del PHP productivo.

## 9. Pruebas sin conexión a OpenVAS

```bash
source .venv/bin/activate
python -m pytest -q
python tools/compare_metadata.py
```

Los XML sintéticos producen una alarma Critical y otra High, descartando Medium/Low/Info. Resultados: validation/metadata/. La referencia actual reproduce el contrato del cliente INSIGHT del servidor (commit 02cb850): snapshot_id/alarms y CVEs como lista; es un ejemplo estructural. Ver [procedencia y alcance](docs/REMOTE_INSIGHT_CONTRACT.md).

La suite incluye un servicio GMP simulado en `127.0.0.1`, con credenciales ficticias y POST al backend bloqueados durante la prueba. Requiere permiso para conexiones loopback; no contacta OpenVAS ni SSH. Para ejecutar únicamente esa prueba:

```bash
python -m pytest tests/test_controlled_gmp.py -q
```

La comparación entre descarga anterior y filtrada queda en `validation/local_controlled/summary.json`. Los tiempos de ese servicio sintético no predicen tiempos del servidor. Ver [el informe local](docs/validation/2026-11-13-local/README.md).

Opcionalmente, con la versión del proyecto del servidor disponible, comparar además su constructor. La copia local antigua de envío individual se marcará incompatible:

```bash
python tools/compare_metadata.py --insight-project ../INSIGHT-MIFIBRA
```

Para procesar XML completos ya exportados:

```bash
python tools/compare_metadata.py --tasks-xml tasks.xml --report-xml report.xml
```

Repetir --report-xml para cada reporte de las tareas. Una comparación estructural aprobada no demuestra conectividad ni aceptación del backend. Los resultados, XML reales, logs, entornos virtuales y secretos quedan excluidos de Git.

## 10. Referencia histórica de validación del servidor

El informe original está en [docs/validation/2026-11-12-nexus/README.md](docs/validation/2026-11-12-nexus/README.md). Se corrigieron la pérdida de configuración entre captura y comparación y la repetición de metadata al paginar XML locales. La lectura local conserva los XML originales y crea páginas compactas para normalizar los resultados.

Primero reprocesar la captura existente, sin conectarse a OpenVAS ni enviar alarmas:

```bash
source .venv/bin/activate
python tools/compare_metadata.py \
  --tasks-xml validation/metadata_live_single_task/captured_xml/tasks.xml \
  --report-xml validation/metadata_live_single_task/captured_xml/report_0000.xml \
  --report-max-kb 30720 \
  --output validation/metadata_reprocessed
```

Para los XML locales se usan los límites predeterminados o los indicados por argumentos; no se cargan credenciales del .env. El comando --live carga una sola configuración del .env y la conserva también durante la comparación. Los argumentos --report-max-kb y --pagination-max-kb permiten ajustar límites explícitamente en ambos modos.

Después probar una sola tarea con GVM_TASK_IDS en un .env propio del proyecto, y usar un directorio nuevo de salida:

```bash
python tools/compare_metadata.py --live --output validation/metadata_live_retest
```

Revisar comparison.json y capture_metrics.json antes de ampliar a las demás tareas. Las métricas identifican tarea, reporte, página, tamaño de respuesta y tráfico acumulado; el XML combinado tiene su tamaño propio. Si se alcanza un límite, no seguir aumentándolo sin identificar el reporte y comprobar los recursos disponibles. La captura guardada posterior de 47 tareas se usa en la [validación de snapshots](docs/validation/2026-11-13-snapshots/README.md). El informe anterior se conserva como historial.

Para el flujo actual de entrega completa, reintentos, migración SQLite y controles, ver [docs/DELIVERY.md](docs/DELIVERY.md). Al actualizar instalaciones existentes, fijar BACKEND_ALARM_TYPE=Alarma de seguridad de OpenVAS x TXDXSecure en su .env; Git no modifica ese archivo privado.

## Cron semanal

OpenVAS está programado con el usuario desarrollo-xoc para domingos a las 09:00
(America/Lima), usando scripts/run_weekly_delivery.sh y BACKEND_ENABLED=true en
el .env del servidor. La entrada de INSIGHT-MIFIBRA se dejó comentada por
licencias, según instrucción del usuario. MAD conserva su programación.
El launcher run_weekly_validation.sh sigue disponible para pruebas sin envío.
Ver [configuración y controles](docs/CRON.md).

La [prueba autorizada del endpoint real](docs/validation/2026-11-13-endpoint/README.md) confirmó 1.258 registros y el rechazo de la repetición idéntica por llave compuesta. Se corrigieron IDs ISO UTC, ACK de repetición, timeout y confianza TLS configurable. La prueba mantuvo el cron sin envío; después se autorizó el cron de producción descrito arriba. No hay descargas automáticas a la laptop por POST; ver [retención de artefactos](docs/DELIVERY.md).
