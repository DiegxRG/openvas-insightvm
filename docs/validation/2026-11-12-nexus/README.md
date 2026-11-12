# Prueba manual de Nexus — 12 de noviembre de 2026

## Alcance y procedencia

Proyecto probado: `/home/steve-ricapa/DESARROLLO/openvas-insightvm`,
commit `83171ddc42018d1d189d321b697fc5b1f81ce881`, rama `main`.
Instalacion independiente junto a MAD-SOPHIA-OP, como `steve-ricapa`,
Python 3.12.15 y entorno `.venv` propio.

Este documento y `observed-results.json` transcriben observaciones de la
sesion de prueba. **No sustituyen los XML y logs originales.** Esos archivos
siguen en Nexus: al intentar recuperarlos para esta publicacion, SSH devolvio
`Not allowed at this time` antes de autenticar. No se incluyen credenciales,
archivos `.env`, entornos virtuales ni capturas de otras integraciones.

`BACKEND_ENABLED=false` durante todas las pruebas. El comando comparador
fuerza ademas el backend deshabilitado en la captura. No se ejecutaron
`main.py`, servicios nuevos, cron ni envios de alarmas. Se verificaron sin
cambios los hashes del `.env` del MAD y de sus dos unidades systemd.

## Resultados observados

- Instalacion de `requirements.txt`: codigo 0.
- `python -m pytest -q`: **24 passed in 0.24s**.
- TCP a `10.208.232.43:41000`: accesible; autenticacion GMP correcta.
- Consulta de tareas: 47 tareas, respuesta de 127351 bytes.
- Primer reporte consultado: dos paginas solicitadas de 250 resultados,
  ambas devolvieron 250; tamanos 5618890 y 5672354 bytes.
  `result_count/filtered`: 1300 en ambas paginas.
- No se valido la paginacion de los otros reportes individualmente.

Primera captura completa, configuracion de ejemplo (20000 KiB):

```text
Live capture failed: Listado completo supera OPENVAS_REPORT_MAX_KB
```

Se modifico **solo el proyecto nuevo** a `OPENVAS_REPORT_MAX_KB=65536`.
Segunda captura completa: mismo error y codigo 1. Ninguna de esas dos
capturas genero el JSON final ni los XML de salida del comparador.

Tercera prueba: una tarea con reporte, seleccionada con `GVM_TASK_IDS` en
un archivo temporal privado. La captura real termino y guardo XML, pero
la fase posterior de comparacion fallo con el mismo limite. Archivo
temporal de credenciales eliminado al finalizar.

Fragmento de la traza de esa tercera prueba:

```text
tools/compare_metadata.py:170 main -> compare(...)
tools/compare_metadata.py:108 compare -> OpenVASCollector(client).collect(...)
openvas_pull/collector.py:62 collect -> self.pages(...)
openvas_pull/collector.py:31 pages
ValueError: Listado completo supera OPENVAS_REPORT_MAX_KB
```

No existen `comparison.json` ni `openvas_prepared_backend.json` de una
comparacion real aprobada. No confundir los tests sinteticos aprobados
con una validacion productiva completa.

## Diagnostico para corregir en codigo

1. `capture_live()` carga el `.env`, pero `compare()` crea otro `Settings`
   con los valores predeterminados: vuelve a **20000 KiB** para procesar
   los XML capturados. No propaga el limite de 65536 KiB de la captura.
2. `XMLFileClient.page()` vuelve a parsear el XML combinado en cada pagina.
   Quita los resultados no seleccionados, pero serializa el resto del
   documento junto con los resultados de esa pagina. Por tanto **no es
   exacto afirmar que siempre devuelve todos los resultados**: si existen
   bloques de metadata grandes, estos pueden repetirse en cada pagina.
3. `OpenVASCollector.pages()` suma los bytes de todas esas respuestas.
   Distinguir el limite por respuesta, el del XML combinado y el del
   trafico acumulado de paginas. Medir sus tamanos antes de cambiar la
   politica; no seguir aumentando limites sin control.
4. La captura completa tambien supero 65536 KiB. La salida no identifica
   que reporte/listado lo causo. La consulta acotada demuestra que el
   primer reporte devuelve paginas del tamano solicitado, pero no permite
   generalizar ese comportamiento a los 47 trabajos.

Anadir pruebas con reportes grandes, varias paginas y metadata fuera de
`results`, incluyendo propagacion de ajustes entre captura y comparacion.
Mantener el bloqueo de POST al backend y rechazar capturas incompletas.
No se ha modificado el codigo del proyecto para ocultar este fallo.

## Evidencia original pendiente de incorporar

Rutas relativas al proyecto en Nexus:

```text
validation/metadata_live.run.log
validation/metadata_live.exit
validation/metadata_live.run2.log
validation/metadata_live.run2.exit
validation/metadata_live_single_task.run.log
validation/metadata_live_single_task.exit
validation/metadata_live_single_task/captured_xml/tasks.xml
validation/metadata_live_single_task/captured_xml/report_0000.xml
validation/mad-readonly-baseline.json
```

El reporte XML capturado ocupa 7589272 bytes; `tasks.xml`, 2793 bytes.
Son datos internos reales: revisar secretos antes de publicarlos.
No hay checksums originales recuperados para afirmar identidad de copias.

La prueba manual tenia prioridad nice 10, limite de espacio virtual de
640 MiB, limite de CPU de 300 segundos y timeout de 600 segundos. Los
fallos observados fueron del limite de XML, no de esos topes de recursos.
