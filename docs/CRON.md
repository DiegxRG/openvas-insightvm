# Cron de OpenVAS MiFibra: recolección sin envío

Ubicación del proyecto en el servidor:
`/home/desarrollo-xoc/DESARROLLO/openvas-insightvm`.
Se utiliza el crontab del usuario `desarrollo-xoc`, conservando la entrada de
INSIGHT-MIFIBRA y sin modificar MAD ni sus servicios.

```cron
# BEGIN OPENVAS_MIFIBRA_COLLECTION_ONLY
CRON_TZ=America/Lima
0 9 * * 0 /bin/bash /home/desarrollo-xoc/DESARROLLO/openvas-insightvm/scripts/run_weekly_validation.sh
# END OPENVAS_MIFIBRA_COLLECTION_ONLY
```

El horario coincide con Insight: domingos a las 09:00, hora de Lima. El cron
está activo para recolectar; **no está habilitado para enviar alarmas**.
El wrapper calcula la raíz del proyecto, usa `.venv/bin/python`, ejecuta una
sola corrida con `--once --no-backend` y aplica umask 077. Un bloqueo flock
impide corridas simultáneas del wrapper (código 75 si ya hay una activa).

La opción `--no-backend` fuerza backend_enabled=False después de cargar el
.env. No envía snapshots ni drena pendientes SQLite, aunque el .env diga
BACKEND_ENABLED=true. No modifica .env ni estados pendientes. El colector sí
consulta GMP y mantiene el filtro de altas/críticas. La SQLite de producción
queda reservada para cuando se autorice la entrega.

Salida del cron: `cloud_audit_log/cron.log`. El log de aplicación conserva su
configuración en .env. Los JSON quedan en el PAYLOAD_DIR configurado
(predeterminado `runtime/openvas/artifacts/`), incluyendo
`snapshot_request_latest.json`, `prepared_backend_latest.json`,
`filtered_latest.json` y `run_latest.meta.json`.

Diferencias respecto del cron de Insight:

- Se utiliza `.venv` de OpenVAS, no el `venv` de Insight.
- Se fuerza `--no-backend` para garantizar la fase sin envío.
- No se pasa `--no-persist-payloads`: OpenVAS conserva los JSON para revisión
  y no admite esa opción en su CLI.
- Se añade un bloqueo para evitar solapamientos del cron de OpenVAS.

El bloqueo no coordina Insight y OpenVAS: son proyectos independientes y ambos
conservan el horario solicitado. No se deshabilita ni sustituye el cron de Insight.

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
La aceptación del snapshot_id textual UUID, la idempotencia por
(finding_id,snapshot_id), la atomicidad del snapshot, la separación por origen
y la semántica de cierres permanecen **sin confirmar**. Se necesita el código
PHP y el esquema/migraciones de sus tablas para probarlos contra una base
exclusivamente de pruebas. No se hicieron solicitudes al backend real.

El wrapper es intencionalmente de recolección sin envío. Habilitar entrega
requerirá una modificación explícita del cron/launcher después de validar el
receptor; cambiar solo BACKEND_ENABLED en .env no activará los POST de este cron.
