# Prueba controlada local de filtrado GMP — 13 de noviembre de 2026

## Hallazgo

La petición anterior de este proyecto utilizaba `levels=hmlg` y normalizaba todos
los resultados antes de descartar Medium/Low/Info localmente. Eso limitaba las
alarmas enviadas, pero no evitaba descargar esas otras severidades.

Se revisó en modo lectura `MAD-SOPHIA-OP/openVAS_integration/gvm_client.py`:
sus rutas TCP plano y python-gvm solicitan `levels=chmlgio`. El transporte,
autenticación, consulta de tareas/reportes y paginación son similares. MAD está
orientado a recopilar varias severidades; no es una referencia de filtrado
temprano para este caso. Su código, configuración y servicios no se modificaron.

La generación del JSON MiFibra ocurre después de la extracción. No exige que el
transporte descargue un conjunto mayor de resultados que los solicitados.

## Corrección y fundamento

- Se solicita `severity>6.9` para High y Critical, usando el filtro
  de resultados de `get_reports` con un `report_id`. Para una sola severidad se
  usa el rango correspondiente. Se aplica paginación sobre los resultados que
  coinciden con el filtro, no sobre todos los resultados antes de filtrarlos.
- Se pide `lean=1`, sin notas ni descripciones de overrides, conservando detalle
  de los resultados. Es configurable mediante `GVM_LEAN_REPORT`.
- La validación local rechaza respuestas que ignoran el filtro o el tamaño de
  página. No se amplía la petición a todas las severidades como fallback.
- Se evita recorrer en mayúsculas todo el buffer en cada paquete y parsear por
  segunda vez el XML de respuesta. Se conserva la detección de declaraciones
  XML peligrosas incluso si llegan separadas en paquetes de un byte.
- Espera de conexión/inactividad: 120 s. Plazo total por página: 600 s. Una
  respuesta que entrega datos lentamente no puede prolongarse indefinidamente.

La [especificación GMP 22.7](https://docs.greenbone.net/API/GMP/gmp-22.7.html#command_get_reports)
documenta `filter` para resultados, `severity`, `first`, `rows`, `lean` e
`ignore_pagination`. La versión concreta desplegada en Nexus y su respuesta
al filtro deben comprobarse en la prueba real posterior.

Corrección tras consultar GMP 22.7 real: el primer commit (9f7301f) usaba dos
límites sin `and`. GMP los combinó por OR, incluyendo resultados inferiores a
7.0. El simulador inicial asumía AND incorrectamente. Se corrigieron cliente y
simulador, y se añadió una regresión que reproduce esa respuesta. La validación
local estricta detuvo la captura real en la primera página, sin envíos. La
consulta de hasta 10 resultados confirmó que el límite único devuelve solo
High/Critical y que `and` explícito funciona para el rango High.

## Ejecución local

Se levantó un servicio GMP ficticio en 127.0.0.1 y se utilizó el cliente TCP real,
incluida autenticación ficticia, encuadre XML y paginación. Se comparó la petición
anterior con la nueva sobre 1300 resultados: 50 Critical, 150 High y 1100 de
otras severidades. Los CVSS incluyen los límites 0.0, 3.9, 6.9, 7.0, 8.9, 9.0 y
10.0. Se bloqueó requests.Session.post durante estas pruebas.

| Medición local | Consulta anterior | Consulta corregida |
|---|---:|---:|
| Resultados recibidos | 1300 | 200 |
| Páginas de reporte | 6 | 1 |
| Bytes transferidos de reportes | 2879613 | 442773 |
| Hallazgos altos/críticos conservados | 200 | 200 |

La reducción de bytes en este escenario es aproximadamente 84,6 %. Coincidieron
exactamente los identificadores de los hallazgos elegibles y los 200 JSON de
alarmas preparados por el constructor MiFibra, sin errores de validación.
También se probó un
servidor que ignora el filtro: la captura fue rechazada. Los rangos individuales
recuperaron 50 Critical y 150 High. La prueba de plazo total y la de declaraciones
XML fragmentadas también pasaron.

La primera ejecución dentro del sandbox bloqueó conexiones loopback con
WinError 10013. Se repitió la prueba con permiso de ejecución para ese servicio
local y pasó. Ese bloqueo no se contabiliza como un fallo de filtrado.

## Límites de la conclusión y siguiente fase

No se contactó al OpenVAS real, no se abrió SSH y no se enviaron alarmas. Estos
datos son sintéticos, no evidencia de resultados productivos ni una estimación
del tiempo real de consulta. El detalle de la ejecución está en
`validation/local_controlled/summary.json`, fuera de Git.
El JSON preparado de ejemplo se guarda en
`validation/local_controlled/prepared_backend.json`; contiene exclusivamente
datos ficticios del servicio local.

Después de publicar y actualizar las correcciones, ejecutar en Nexus una sola
tarea en un directorio nuevo, con BACKEND_ENABLED=false. Revisar el filtro,
received_severities, request_seconds y tamaños en capture_metrics.json. Verificar
el JSON preparado y después ampliar la consulta a más tareas. Si el servidor
rechaza la sintaxis o ignora el filtro, detenerse y revisar su versión/respuesta;
no volver automáticamente a una descarga completa.
