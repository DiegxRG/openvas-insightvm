# Validación de la capa persistente de entrega

Código implementado: d6e421f. La prueba utiliza los JSON privados previamente
descargados de OpenVAS: 1258 alarmas y 2301 ocurrencias de 47 reportes.
Los archivos operativos no se publican; solo se incluyen agregados.

## Pruebas locales

Suite completa: **68 passed**. Incluye:

- Confirmaciones persistentes entre procesos nuevos y tras reinicio.
- Cambios de severidad, CVSS, CVEs, título/hostname y puertos.
- Ignorar fechas/UUID de observación y orden de CVEs como cambios espurios.
- Primera entrega, hallazgos nuevos, reaparición y cambios A → B → A.
- Ausencia solo tras snapshot completo; parciales no cierran ni hacen perder
  identidades nuevas, y snapshots antiguos no revierten observaciones recientes.
- Backoff, conflictos pendientes, HTTP 500 con success=true, reintento tras
  caída del colector, contexto de ocurrencias conservado y orden FIFO por finding.
- Enqueue transaccional, corrupción/esquema desconocido, concurrencia y
  liberación del lock tras muerte del proceso.
- Caso ambiguo de éxito HTTP seguido de fallo de guardado: se conserva el
  pendiente y se reintenta, en lugar de afirmar una entrega sin confirmación.

## Escenario con las 1258 alarmas guardadas

Se usó una SQLite nueva en validation/delivery_release_20261113 y un transporte
en memoria. El destino configurado era backend-simulated.invalid y session.post
fue sustituido por un stub. No se contactó al backend real ni a GMP.

| Escenario | Peticiones simuladas |
|---|---:|
| Primera corrida | 1258 |
| Segunda corrida idéntica, nuevo cliente/misma base | 0 |
| Crítica nueva + cambios en CVEs/título/puerto | 4 |
| Repetir esos cambios | 0 |
| Desaparición completa y reaparición | 1 |
| Pendientes al terminar | 0 |

Los objetos entregados en la primera corrida coincidieron exactamente con los
JSON originales de 13 campos. El colector no se modificó. La cola no alteró ni
redujo el JSON preparado de revisión. Duración medida del escenario: 1,613 s;
ese tiempo de un stub no predice el tiempo del backend real.

## Operación y límites

Ver [DELIVERY.md](../../DELIVERY.md) para arquitectura, huellas, retención,
backup y control de reintentos/reenvíos. SQLite y locks se usan en disco local,
no como coordinación entre múltiples servidores. Los pendientes nunca se purgan
automáticamente. Un conflicto del backend no confirma una actualización.

El agente reduce duplicados normales y conserva todos los pendientes, pero
no promete exactamente una vez ante el fallo entre HTTP y el ACK local: esa
última garantía exige idempotencia en el backend. También hace falta que el
backend acepte actualizaciones/upsert para aplicar los cambios ya encolados.

Se intentó repetir las pruebas simuladas en el servidor. SSH cerró la conexión
durante la autenticación y el siguiente intento fue cerrado antes del acceso.
No se hizo pull remoto de esta versión ni se activó el backend productivo.
No se creó ni precargó una base productiva con ACK ficticios.

Cuando vuelva el acceso, desde openvas-insightvm en el servidor:

```bash
git pull --ff-only origin main
source .venv/bin/activate
python -m pytest -q
python tools/test_delivery_controlled.py \
  --prepared validation/all_high_critical_qod0_20261113_103601/openvas_prepared_backend.json \
  --findings validation/all_high_critical_qod0_20261113_103601/openvas_filtered.json \
  --output validation/delivery_controlled_server_NEW
```

El directorio de salida debe ser nuevo. Mantener BACKEND_ENABLED=false. La
herramienta no usa la base productiva ni un transporte HTTP real. Las nuevas
variables tienen valores predeterminados y no añaden dependencias pip.
