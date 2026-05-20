# Secure Code Review — haak-anvil

**Fecha:** 2026-05-20
**Versión revisada:** 0.1.0
**Alcance:** 100% del código fuente Python + plantilla Jinja2 + `pyproject.toml`.
**Metodología:** análisis estático con mentalidad ofensiva. El input de la
herramienta (XML de Nmap/Nessus) se trata como **dato no confiable**: hostnames,
banners de servicios y descripciones son controlables por un atacante que
posea un activo dentro del alcance del escaneo.

## Resumen

7 hallazgos. **6 corregidos** en este commit; 1 informativo documentado.

| ID | Hallazgo | Severidad | Estado |
|----|----------|-----------|--------|
| HAK-001 | XSS almacenado — autoescape de Jinja2 inactivo | Alta | ✅ Corregido |
| HAK-002 | Path traversal vía `engagement.id` | Alta | ✅ Corregido |
| HAK-003 | SSRF latente en el enricher de CVE | Media | ✅ Corregido |
| HAK-004 | DoS por archivo XML sin límite de tamaño | Media | ✅ Corregido |
| HAK-005 | Inyección de estructura en Markdown | Baja | ✅ Corregido |
| HAK-006 | `engagement.yaml` sin límite de tamaño | Baja | ✅ Corregido |
| HAK-007 | Tailwind CSS por CDN sin SRI | Informativa | ⏳ Documentado |

## Detalle

### HAK-001 — XSS almacenado (Alta)

`renderers/html.py` usaba `select_autoescape(["html", "xml"])`. La plantilla se
llama `default.html.j2`; `select_autoescape` evalúa la **última** extensión
(`.j2`), que no está en la lista → el autoescape **nunca se activaba** y ninguna
variable se escapaba. Un atacante que controla un host escaneado inyecta
`<script>` en el banner de un servicio → Nessus lo captura en `plugin_output` →
llega a `finding.evidence` → se ejecuta JS al abrir el reporte HTML.

**Fix:** `autoescape=True` (escapa todas las plantillas del `Environment`).

### HAK-002 — Path traversal vía `engagement.id` (Alta)

`RendererBase.write()` usaba `engagement.id` sin sanitizar como nombre de
archivo de salida. Un `id` con `../../` en un JSON bundle de terceros permitía
escribir fuera del directorio destino.

**Fix:** `field_validator` en `Engagement.id` (solo `[\w-]{1,64}`) + `re.sub`
defensivo en `write()`.

### HAK-003 — SSRF latente en el enricher de CVE (Media)

`CveEnricher._fetch_cve()` pasaba `cve_id` a una petición HTTP sin validar el
formato. Riesgo latente de cara a la Fase 2 del enricher.

**Fix:** validación estricta `^CVE-\d{4}-\d{4,7}$` antes de la llamada HTTP.

### HAK-004 — DoS por XML gigante (Media)

`defusedxml` protege contra XXE y billion-laughs, pero no contra un XML bien
formado de varios GB que agota la memoria del proceso.

**Fix:** `ParserBase._guard_file_size()` aborta antes de parsear si el archivo
supera el límite (256 MB por defecto, configurable con `HAAK_ANVIL_MAX_XML_MB`).

### HAK-005 — Inyección de estructura en Markdown (Baja)

El renderer de Markdown interpolaba `hostname`, `os` y títulos de findings sin
escapar `|`, `\` ni saltos de línea — rompía tablas o inyectaba encabezados.

**Fix:** helper `_md_escape()` aplicado a los campos de origen no confiable.

### HAK-006 — `engagement.yaml` sin límite de tamaño (Baja)

`Engagement.from_yaml()` cargaba el archivo completo en memoria sin límite.

**Fix:** límite de 1 MB antes de `yaml.safe_load`.

### HAK-007 — Tailwind CSS por CDN sin SRI (Informativa)

El reporte HTML carga `https://cdn.tailwindcss.com` sin Subresource Integrity:
depende de red para renderizar, puede disparar DLP del cliente y expone a un
compromiso de cadena de suministro. **Recomendación v0.2:** empaquetar el CSS
como asset estático e incrustarlo inline.

## Lo que ya estaba bien

`defusedxml` en ambos parsers (sin XXE), `yaml.safe_load`, deserialización vía
Pydantic v2 (sin `pickle`/`eval`), cero `subprocess`/`os.system`, y `httpx` con
sus defaults seguros (`verify=True`, `follow_redirects=False`).

## Regresión

Tests añadidos en `tests/test_security.py` que fijan HAK-001, HAK-002 y HAK-005.
Suite completa: 28 passed.
