# Referencia INSIGHT encontrada por SSH

## Procedencia y alcance

Revisión de solo lectura del 13 de noviembre de 2026:

- Carpeta: `/home/desarrollo-xoc/DESARROLLO/INSIGHT-MIFIBRA`.
- Repositorio: `https://github.com/DiegxRG/INSIGHT-MIFIBRA`.
- Commit revisado: `02cb850` (`actualiza deduplicacion por snapshot`).
- Archivos: `insightvm_pull/backend_client.py`, `README.md`, `docs/INSIGHT.md`.

Esta copia difiere de la carpeta local usada inicialmente para comparar los
JSON de OpenVAS. Las comparaciones anteriores con 13 campos y CVEs como texto
eran válidas contra aquella implementación local; no certifican este contrato
remoto más reciente. No se encontraron archivos PHP/SQL en esta carpeta ni PHP
embebido en los documentos revisados. La implementación del receptor real
continúa pendiente de inspección; sus tests usan un receptor simulado.

## Contrato de envío observado en el código remoto

Un único POST con:

```json
{
  "snapshot_id": "2026-11-13T01:00:00Z",
  "alarms": []
}
```

`alarms` contiene la foto completa actual cuando hay altas o bajas. Cada alarma
mantiene 13 campos, pero `cves` es una lista JSON, no una cadena. El código fija
`TipoAlarma` y `source` a etiquetas propias de InsightVM; OpenVAS debe utilizar
su identidad y los valores de origen acordados, no fingir ser InsightVM.

`snapshot_id` se coloca en el envoltorio. El documento `docs/INSIGHT.md` propone
la llave `(finding_id, snapshot_id)` para cabecera y detalle histórico, y muestra
también un ejemplo de alarma con snapshot_id propio. Para saber cuál acepta el
receptor productivo hay que inspeccionar PHP/BD; el emisor implementa el ID en
el envoltorio.

## Comprobación controlada ejecutada en el servidor

Se importó el cliente remoto con escritura de bytecode deshabilitada, datos
ficticios y baseline en un directorio temporal. session.post se sustituyó por
un stub; no hubo POST reales ni cambios en la instalación de INSIGHT.

| Escenario | POST | Alarmas en el POST |
|---|---:|---:|
| Primera captura de 100 | 1 | 100 |
| Cambian 5 CVSS, mismos 100 IDs | 0 | 0 |
| Se agregan 5 IDs nuevos | 1 | 105 |
| Se conservan solo 70 IDs | 1 | 70 |

La prueba confirmó las claves de envoltorio snapshot_id/alarms, 13 campos por
alarma y CVEs como lista. Se mantuvo BACKEND_NOTIFY_NO_CHANGES=false.

## Implicaciones para OpenVAS

OpenVAS fue adaptado al envoltorio de snapshot completo y CVEs como lista.
Conserva SQLite para snapshots inmutables, orden FIFO y reintentos, y compara
contenido semántico para detectar también cambios de CVSS/CVEs. La adaptación
está documentada en [DELIVERY.md](DELIVERY.md); el JSON antiguo descargado debe
regenerarse desde los hallazgos guardados antes de usarlo con este contrato.
El snapshot_id de OpenVAS se corrigió a ISO 8601 UTC con segundos, igual al
formato exigido por el endpoint en una prueba manual posterior. SQLite mantiene
un reloj por ámbito para evitar colisiones y conserva el ID en cada reintento.
Los UUID iniciales fueron rechazados explícitamente por el receptor.

No hay evidencia de una operación de cierre implementada. Una ausencia en el
último snapshot no demuestra por sí sola resolución: se necesita cobertura de
escaneo, ámbito de origen y confirmación de snapshot completo. No se deben
borrar históricos ni enviar cierres nuevos suponiendo campos/endpoints que no
están definidos. Un snapshot vacío completo y una notificación sin cambios
deben distinguirse y el receptor debe conocer el origen incluso sin alarmas.

El backend real permanece deshabilitado. Esta revisión documenta el emisor y
la propuesta, no confirma que el PHP productivo ya implemente la llave ni la
reconciliación de cierres.

## Inspección de la carpeta backend

Se revisaron backend/server.py y backend/view_model.py: corresponden a un visor de JSON con GET, sin recepción POST, escritura de alarmas, deduplicación ni cierres. La prueba aislada mostró las 1.258 alarmas de OpenVAS sin perder campos de detalle; duplicar la entrada duplicó las filas. No equivale a validar guarda_alarma.php, ubicado según configuración en 10.208.232.208. El cron se prepara con envío forzado a deshabilitado; detalles en [CRON.md](CRON.md).
