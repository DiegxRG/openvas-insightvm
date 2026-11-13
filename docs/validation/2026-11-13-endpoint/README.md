# Envío controlado al endpoint — 13 de noviembre de 2026

Esta prueba fue autorizada expresamente para el receptor real, después de las
validaciones sin envío. Se usaron las 1.258 alarmas altas/críticas guardadas,
Local=Mi Fibra, source=openvas, 13 campos y CVEs como lista. No se consultó GMP
nuevamente y no se ejecutaron pruebas de cierres ni snapshots reducidos/vacíos.

La primera conexión no envió HTTP por rechazo TLS del certificado autofirmado.
Se obtuvo su certificado y la prueba verificó TLS con ese PEM explícito y el
SAN de la IP, sin usar verify=false. El certificado no proviene de una CA pública.
El primer POST HTTP fue rechazado por snapshot_id UUID. Se corrigió el formato
a ISO 8601 UTC con segundos, tal como exige explícitamente el receptor.

| POST | Resultado |
|---|---|
| Inicial con UUID | HTTP 200, success=false: formato de snapshot_id inválido |
| Snapshot válido de 1258 | HTTP 200, success=true, registros_exitosos=1258 |
| Repetición idéntica | HTTP 200, success=false, 1258 errores de llave duplicada |

Snapshot válido: `2026-11-13T20:10:31Z`. Ambos POST válidos tuvieron exactamente
el mismo cuerpo de 644.671 bytes y SHA-256:
`35ee4ceb98ee6687bf6f2290c8ea8f6d113c6a163af4372d9723f2a385767500`.
Primera inserción: 35,373 s. Repetición: 0,690 s. Todos los errores repetidos
corresponden a la misma combinación finding_id/snapshot_id del JSON enviado;
no hubo otra causa de rechazo. El receptor reporta guardar las 1.258 iniciales
y rechazar las 1.258 repetidas; no hubo acceso directo a su BD para contar filas.

Correcciones derivadas: IDs UTC y reloj SQLite persistente (esquema 3), ACK
estricto de repetición completa, timeout de backend de 180 segundos y confianza
TLS mediante BACKEND_CA_BUNDLE. Una cola antigua con UUID pendientes se conserva
y bloquea la migración hasta reconciliarla, sin cambiar IDs en silencio.

El cron conserva --no-backend, y BACKEND_ENABLED permanece false. No se sembró
la SQLite productiva con el estado de esta prueba. Los JSON completos y respuestas
por hallazgo permanecen en validation/ del servidor, excluidos de Git; no se
copiaron automáticamente a ninguna laptop. Los archivos *_latest.json del flujo
normal se sobrescriben, mientras SQLite conserva cola y auditoría con su retención.

La aceptación del snapshot y el rechazo de sus duplicados sí se comprobaron.
La separación de cierres por origen y la reconciliación de ausencias siguen sin
validarse; esta prueba no cerró alarmas deliberadamente.
