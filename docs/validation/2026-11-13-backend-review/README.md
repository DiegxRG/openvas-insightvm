# Revisión del JSON final, agrupación y duplicados

## Contrato

Se compararon las 1258 alarmas de la captura completa con el constructor actual
de INSIGHT-MIFIBRA usando los mismos findings. El JSON completo preparado coincidió
exactamente: cinco claves de envoltorio y 13 campos por alarma. No se enviaron
alarmas reales. `source=openvas`, los IDs de activo y el OID corresponden al
origen OpenVAS; el formato y tipos mantienen el contrato INSIGHT.

## Auditoría contra los XML originales de 47 reportes

Se reconstruyeron independientemente los grupos IP/NVT, las ocurrencias
reporte/tarea/puerto y la unión de CVEs desde los XML conservados en el servidor.

| Comprobación | Resultado |
|---|---:|
| Ocurrencias altas/críticas de origen | 2301 |
| Grupos únicos IP/NVT de origen | 1258 |
| Alarmas preparadas | 1258 |
| Grupos perdidos o adicionales | 0 |
| Ocurrencias perdidas o adicionales | 0 |
| Grupos con pérdida de CVEs | 0 |
| Críticas representadas como altas | 0 |
| Grupos críticos esperados / alarmas críticas | 236 / 236 |
| Alarmas altas | 1022 |
| finding_id duplicados en el JSON | 0 |

En esta captura no se encontró pérdida. Las 1043 ocurrencias que no generan
alarmas adicionales están agrupadas bajo su equipo/NVT y permanecen en el JSON
de detalle; no son vulnerabilidades distintas eliminadas por un cupo.

Se detectó además un riesgo en el algoritmo anterior: priorizaba la fecha sobre
la puntuación, por lo que una observación High posterior podía representar a un
grupo que también contenía Critical. Aunque no ocurrió en estos datos reales,
se corrigió para conservar el mayor CVSS y usar la fecha como desempate. Las
ocurrencias nuevas conservan resultado, severidad, puntuación, fecha y CVEs,
además de reporte, tarea y puerto. No se añaden campos al contrato backend.

Las pruebas incluyen los dos órdenes de llegada para Critical anterior/High
posterior y verifican que no se mezclen los CVEs de las ocurrencias individuales.

## Alcance real de la protección contra duplicados

La agrupación local produce un finding_id estable y una alarma por IP/NVT dentro
de una captura. Eso se verificó con los datos reales y con replay sintético.

No existe actualmente un registro local persistente de alarmas ya enviadas.
Repetir dos envíos de las 1258 alarmas contra un backend simulado que acepta
todo produjo 2516 llamadas, con los mismos 1258 IDs solicitados dos veces. Es
una prueba del cliente, no una inserción de duplicados en la base real.

Con un backend simulado que rechaza IDs ya vistos, la primera ejecución registró
1258 éxitos y la segunda 1258 conflictos. El cliente clasificó correctamente
`Ya existe un registro activo`, pero siguió realizando las peticiones: el
rechazo depende del backend.

No se inspeccionó el código/base del backend real ni se hicieron POST para
certificar su unicidad. Antes de afirmar que hay antiduplicación entre corridas,
hay que verificar que el backend aplique una clave apropiada por origen,
equipo y vulnerabilidad, y que permita las transiciones de cierre/reapertura.
La protección local persistente sería una función adicional y requeriría definir
cuándo reenviar cambios y reaperturas; no se inventó esa política en esta revisión.
