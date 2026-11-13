# Validación de snapshots completos — 13 de noviembre de 2026

Pruebas locales del colector y entrega con backend simulado. No se enviaron
solicitudes al backend real ni se abrió una nueva consulta al OpenVAS remoto.

Se reutilizaron los JSON de la captura guardada de 47 tareas: 1.258 grupos de
alarmas altas/críticas (2.301 ocurrencias). El constructor nuevo regeneró las
alarmas sin truncar grupos, con snapshot_id/alarms y 13 campos por alarma,
incluidos CVEs como lista. El resumen no contiene IPs ni hallazgos privados.

| Escenario sobre datos guardados | POST simulado | Alarmas |
|---|---:|---:|
| Inicial | 1 | 1258 |
| Idéntico después de reiniciar cliente | 0 | — |
| Solo cambio de CVSS | 1 | 1258 |
| Solo cambio de CVEs | 1 | 1258 |
| Alta sintética crítica | 1 | 1259 |
| Repetición idéntica | 0 | — |
| Retirada del alta sintética | 1 | 1258 |
| Reaparición | 1 | 1259 |
| Captura completa vacía | 1 | 0 |
| Misma captura vacía | 0 | — |

Pendientes finales: 0. Todos los POST fueron llamadas a un stub en memoria.
El JSON de revisión y la SQLite simulada permanecen en validation/ local,
excluidos de Git. El archivo de revisión inicial contiene las 1.258 alarmas
originales; los cambios sintéticos solo se aplican en memoria.

La suite también cubre 100→105→70, cambios sin nuevos IDs, puertos, orden de
CVEs, reinicios reales de proceso, bloqueo entre emisores, fallo de ACK local,
reintentos de payload/ID exactos, FIFO, A→B→A, captura parcial/fallida,
retención, migración desde esquema 1 y estado corrupto. Las pruebas GMP usan
127.0.0.1 con datos ficticios y verifican filtrado previo a descarga.

Esto confirma el emisor y sus reintentos, no la aceptación del PHP ni cierres
productivos. BACKEND_ENABLED permanece false en la configuración local.

Resultado de la suite final: **74 pruebas aprobadas**. Comparación estructural de referencia: aprobada, 13 campos y sin discrepancias de tipos.
