# Diagnóstico y correcciones locales

La revisión del commit b9f3dab confirma dos defectos en el código probado en
83171dd. Estas notas no modifican el informe histórico ni afirman una nueva
validación en Nexus. Los XML originales no están disponibles en este workspace.

1. La captura cargaba el .env, pero la comparación construía Settings con
   valores predeterminados. Perdía límite de XML, tamaño de página y otras
   opciones, incluida la configuración de Local. Ahora --live carga una sola
   configuración y la pasa a ambas fases, forzando backend_enabled=False.
2. El adaptador de archivos volvía a parsear y serializar metadata externa a
   results en cada página. Ahora reutiliza el documento durante sus páginas y
   crea respuestas compactas con los resultados seleccionados y los campos
   necesarios para normalizarlos. El archivo capturado permanece intacto.
3. Antes OPENVAS_REPORT_MAX_KB también se aplicaba a la suma del tráfico de
   páginas, aunque estas repiten metadata. Ahora controla cada respuesta y el
   XML combinado, mientras OPENVAS_PAGINATION_MAX_KB limita el tráfico acumulado
   por listado/reporte. No se elimina la protección contra capturas excesivas.
4. Los errores identifican tarea/reporte/página y tamaño. capture_metrics.json
   conserva la progresión incluso cuando falla la recolección por límite. El
   rechazo de una captura incompleta ocurre antes de preparar alarmas.

La captura original de una tarea medía 7589272 bytes, menor que el límite de
20000 KiB. Eso es compatible con un exceso artificial de tráfico durante su
relectura, por metadata repetida; no prueba por sí solo el tamaño de cada
componente sin examinar el XML original. Una prueba de regresión sintética con
7,5 MB de metadata externa y 501 resultados reproduce esa condición y valida
que los tres grupos de resultados se recuperan sin repetir ese bloque.

La captura completa de 47 tareas también falló con 65536 KiB. Falta identificar
el reporte que lo causó y medir sus páginas en el servidor. No se puede concluir
que era una respuesta individual de más de 64 MiB ni que aumentar el límite
resuelva el problema. Consultar capture_metrics.json en la nueva ejecución.

Siguiente paso: reprocesar el XML de una tarea ya guardado en Nexus usando los
comandos del README principal, revisar las alarmas y luego repetir una captura
de una tarea. Ampliar a otras tareas solo tras verificar tamaños y resultados.
No se requiere tocar MAD, sus unidades systemd ni habilitar POST al backend.
