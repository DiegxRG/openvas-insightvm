# Cron de OpenVAS MiFibra: envío semanal

Ubicación: `/home/desarrollo-xoc/DESARROLLO/openvas-insightvm`.
Usuario del crontab: `desarrollo-xoc`.

Por autorización del usuario del 13 de noviembre de 2026 se habilita OpenVAS
y se comenta la entrada de INSIGHT-MIFIBRA por el motivo de licencias indicado.
No se elimina el proyecto Insight ni se modifica MAD o sus servicios.

```cron
# BEGIN OPENVAS_MIFIBRA_DELIVERY
CRON_TZ=America/Lima
0 9 * * 0 /bin/bash /home/desarrollo-xoc/DESARROLLO/openvas-insightvm/scripts/run_weekly_delivery.sh
# END OPENVAS_MIFIBRA_DELIVERY
```

Domingos a las 09:00, hora de Lima. Próxima ejecución tras la activación:
15 de noviembre de 2026 a las 09:00 (America/Lima).

El launcher de producción calcula la raíz, usa `.venv/bin/python` y ejecuta
`main.py --env-file RUTA/.env --once`. El .env del servidor tiene:

```dotenv
BACKEND_ENABLED=true
BACKEND_LOCAL=Mi Fibra
BACKEND_TIMEOUT=180
BACKEND_TLS_VERIFY=true
BACKEND_CA_BUNDLE=runtime/openvas/certs/backend-ca.pem
```

El PEM privado del despliegue y .env no se suben a Git. El certificado debe
revisarse/renovarse al cambiar en el receptor o antes de su vencimiento.
El ejemplo .env.example conserva BACKEND_ENABLED=false: un clon nuevo requiere
habilitación explícita. No se activa el envío en la laptop por este cambio.

Los snapshots completos solo se encolan cuando hay cambios de contenido;
los pendientes se reintentan en FIFO con su mismo ID y JSON. Si GMP falla o
la captura es parcial, no se crea una foto incompleta, pero sí se pueden
reintentar snapshots completos pendientes. Si no cambia nada y no hay pendientes,
la corrida no hace POST. Ver [DELIVERY.md](DELIVERY.md).

Logs del cron: `cloud_audit_log/cron.log`; logs de aplicación según .env.
JSON de revisión: `runtime/openvas/artifacts/`, incluidos snapshot_request_latest.json,
prepared_backend_latest.json, filtered_latest.json y run_latest.meta.json.
Estado persistente: runtime/openvas/delivery.sqlite3, creado al ejecutar el emisor.
Los archivos *_latest se sobrescriben; no se descargan copias a la laptop.

Ambos launchers comparten el bloqueo runtime/openvas/weekly_validation.lock
para impedir solapamiento (salida 75 si está ocupado), y usan umask 077.
`scripts/run_weekly_validation.sh` conserva --no-backend como entrada manual
sin envío; ya no es el comando del cron. Puede usarse para revisar la
recolección sin enviar ni drenar pendientes aunque .env habilite el backend.

La entrada original de Insight se conserva comentada en el crontab y hay
respaldo privado del crontab y .env previos en el servidor. Para suspender
OpenVAS se debe comentar su entrada; BACKEND_ENABLED=false detiene POST y
reintentos, pero conserva la recolección si se mantiene el cron.

## Revisión del receptor

La carpeta `INSIGHT-MIFIBRA/backend` es un visor local. `backend/server.py`
solo define do_GET y `backend/view_model.py` transforma JSON en filas para
mostrar. No recibe POST, no escribe alarmas en BD y no implementa deduplicación
ni cierres. Esto no demuestra un fallo del receptor productivo, porque es otro
componente.

La comprobación aislada con el JSON de OpenVAS mostró 1.258 filas en cada tabla
del visor, CVEs como lista y source=openvas. Duplicar el JSON de entrada mostró
2.516 filas, con 1.258 llaves compuestas repetidas. Un snapshot vacío solo
produce tablas visuales vacías; no cierra registros persistidos.

El receptor configurado es `10.208.232.208/txdxsecure/guarda_alarma.php`, distinto
del servidor SSH `10.208.232.47`. No se encontró PHP/SQL en INSIGHT-MIFIBRA.
La revisión inicial fue sin solicitudes reales. Una [prueba manual posterior
expresamente autorizada](validation/2026-11-13-endpoint/README.md) confirmó la
recepción de 1.258 alarmas y el rechazo de las mismas llaves repetidas. El
receptor exige IDs ISO UTC; rechazó UUID. La atomicidad ante fallos parciales,
la separación por origen y los cierres permanecen sin confirmar. No hubo
pruebas de cierres ni acceso al PHP o su BD.

## Identidad del cliente

La revisión de los .env confirmó el mismo endpoint HTTPS para ambos emisores, pero OpenVAS conservaba BACKEND_LOCAL=Txdxsecure mientras Insight usa Mi Fibra. Se corrigió BACKEND_LOCAL=Mi Fibra en OpenVAS y su configuración de ejemplo/default. TipoAlarma y source mantienen identidad OpenVAS. Esto alinea el campo Local sin afirmar cómo lo interpreta internamente el receptor.

## Reintentos automáticos de pendientes

Se conserva intacta la entrada semanal de los domingos a las 09:00. Una entrada
adicional del mismo usuario desarrollo-xoc despierta el emisor cada minuto:

```cron
# BEGIN OPENVAS_MIFIBRA_PENDING_RETRIES
* * * * * /bin/bash /home/desarrollo-xoc/DESARROLLO/openvas-insightvm/scripts/run_pending_retries.sh
# END OPENVAS_MIFIBRA_PENDING_RETRIES
```

El launcher ejecuta main.py --retry-pending. No construye OpenVASClient ni
OpenVASCollector, no consulta GMP ni encola capturas vacías o nuevas. Solo lee
los snapshots pendientes de DELIVERY_STATE_PATH para el ámbito configurado;
envía exactamente el ID y JSON almacenados. Sin base/pendientes no hace POST.
BACKEND_ENABLED=false o --no-backend también deshabilitan estos reintentos.

Se respeta FIFO y next_attempt: backoff de 60 segundos hasta 3600 segundos por
defecto, con resolución adicional del cron de hasta un minuto. Se conserva la
misma validación estricta de duplicados. Un reintento antiguo no adelanta a otro.
Comparte el bloqueo con el proceso semanal y el launcher de validación; si el
bloqueo está ocupado, termina sin error y vuelve a comprobar al minuto siguiente.
No utiliza --once: --retry-pending ya ejecuta una sola pasada de la cola y sale.

Logs adicionales: cloud_audit_log/retry.log (stdout/stderr del cron) y
logs/retry.log (rotativo, hasta 5 respaldos de 2 MB). Las corridas sin intentos
ni errores no generan mensajes ni actualizan metadata; no se crea historial
JSON por minuto. Los intentos/errores actualizan solo
runtime/openvas/artifacts/retry_latest.meta.json. La metadata semanal
run_latest.meta.json no se sobrescribe por reintentos. La SQLite muestra el
estado final autoritativo: una entrega semanal inicialmente fallida puede
quedar confirmada después por este proceso.

No ejecutar main.py --once para revisar pendientes: vuelve a consultar GMP.
Los comandos de consulta para la revisión están en [VERIFICACION_OPENVAS.txt](VERIFICACION_OPENVAS.txt).
