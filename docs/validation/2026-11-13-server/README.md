# Prueba controlada real de openvas-insightvm — 13 de noviembre de 2026

## Alcance

Se publicaron los cambios, se actualizó main por SSH y se probó una sola tarea
del proyecto `/home/steve-ricapa/DESARROLLO/openvas-insightvm`. Código probado:
`bb8384c24c28075bfd84e7e7ef9169c5f39f7be8`. El GMP remoto informó versión 22.7.

Se utilizó el entorno virtual existente y se mantuvo BACKEND_ENABLED=false. La
captura y comparación también forzaron el backend deshabilitado. No se ejecutó
main.py, no se iniciaron escaneos, servicios ni cron, ni se enviaron alarmas.
No se consultaron ni modificaron otros proyectos del servidor.

## Fallo detectado y corregido durante la prueba

El commit inicial 9f7301f solicitaba dos condiciones de severidad sin `and`.
GMP las combinó por OR y devolvió 250 resultados en la primera página:
220 Info, 15 Low, 14 Medium y 1 High. La validación del cliente rechazó esa
captura antes de preparar alarmas. Duración del intento: 6,268 segundos.

Consultas limitadas a 10 resultados confirmaron lo siguiente:

- `severity>6.9`: 7 resultados, todos High/Critical.
- `severity>6.9 and severity<9.0`: 5 resultados High.
- `levels=hc`: 7 resultados High/Critical.

La corrección bb8384c usa un límite único para High/Critical y `and` explícito
cuando se necesita un intervalo High. Se corrigió también el simulador local,
que antes asumía AND, y se añadió una prueba de regresión de OR implícito.

## Resultado final real

| Medición | Resultado |
|---|---:|
| Tareas visibles consultadas | 47 |
| Tareas cuyos reportes se descargaron | 1 |
| Páginas del reporte descargadas | 1 |
| Resultados High | 5 |
| Resultados Critical | 2 |
| Resultados Medium/Low/Info recibidos | 0 |
| Bytes de respuesta del reporte | 136486 |
| Bytes del XML combinado guardado | 136030 |
| Alarmas preparadas | 7 |
| Campos por alarma | 13 |
| Diagnósticos de descarte | 0 |
| Tiempo total de captura y comparación | 5,364 s |
| POST al backend | 0 |

La comparación de estructura pasó. Las tareas consumieron 126932 bytes y
4,010720 s; la solicitud del reporte filtrado, 1,162136 s. Estos tiempos son una
medición de esta ejecución y no una garantía para otros reportes.

El XML histórico de 7589272 bytes también pudo reprocesarse con el código
corregido en 1,52 s. Contenía 1300 resultados y produjo 5 alarmas High. Los 5
hallazgos aparecen en la captura nueva con iguales puntuaciones; la nueva
incluye además 2 Critical con CVSS 10.0. La consulta histórica pedía
`levels=hmlg`, sin `c`. No se ha probado el conjunto completo de 47 reportes.

## Configuración de esta prueba

Solo se actualizaron opciones del .env de este proyecto: espera de
conexión/inactividad 120 s, plazo por solicitud 600 s, lean=true, XML máximo
30720 KiB, tráfico acumulado máximo 65536 KiB y backend=false. Las credenciales
permanecieron en el servidor. La tarea se restringió mediante Settings durante
la ejecución, sin cambiar permanentemente GVM_TASK_IDS.

El proceso de prueba usó nice 10, memoria virtual máxima de 640 MiB, CPU máxima
de 300 s y una alarma de tiempo total de 900 s.

## Evidencia privada en el servidor

Dentro del proyecto:

```text
validation/live_verified_20261113/openvas_prepared_backend.json
validation/live_verified_20261113/openvas_filtered.json
validation/live_verified_20261113/comparison.json
validation/live_verified_20261113/capture_metrics.json
validation/live_verified_20261113/test_summary.json
validation/live_verified_20261113/baseline_comparison.json
validation/live_verified_20261113/captured_xml/tasks.xml
validation/live_verified_20261113/captured_xml/report_0000.xml
```

Los XML, JSON operativos y credenciales no se publican en Git. Este documento
solo resume mediciones sin nombres de equipos, direcciones de activos ni
contenido de vulnerabilidades. No implica aceptación real del backend ni
validación de todos los reportes disponibles.
