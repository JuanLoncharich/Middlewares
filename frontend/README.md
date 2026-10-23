# mcp-eval-ui

Frontend para presentar mcp-eval-operator en vivo: un servidor MCP entra, se
evalúa en un sandbox y sale un veredicto. Funciona sin cluster (modo demo) o
leyendo los CRs reales (modo live). El toggle Demo/Live está arriba a la
derecha.

## Levantarlo

```bash
cd frontend
npm install
npm run demo          # http://localhost:5173, sin cluster ni backend
```

Modo live, contra el cluster de tu `KUBECONFIG`:

```bash
NAMESPACE=mcp-evals npm run live          # backend en :8787 + vite con proxy
# opcional: conteos de redacción de Occludra
kubectl -n observability port-forward svc/prometheus 9090:9090 &
PROM_URL=http://127.0.0.1:9090 npm run live
```

Abrí `http://localhost:5173/?mode=live`. Para el cluster k0s hace falta la VPN
hacia `10.66.50.0/24`. **Nunca commitees el kubeconfig** (`message.txt` ya
está en `.gitignore`).

Para probar live sin cluster, un API server falso reproduce un escenario de la
demo (watch, pods, logs y el ConfigMap del report):

```bash
npm run fake-api -- vigil           # o approved, exfiltration, degraded
KUBECONFIG=$PWD/test/.fake-kubeconfig npm run live
```

## Para presentar

| Tecla | Acción |
|---|---|
| `1` a `4` | Flujo del prompt, Ciclo de vida, Servidores, Terminal |
| `espacio` | Pausar o reanudar la demo |

El selector Claro/Oscuro de la barra superior cambia el tema y lo recuerda en
el navegador; sin elección, sigue el tema del sistema. Para proyectar conviene
el claro.

La barra de la demo elige el escenario, la velocidad (1×, 2×, 4×) y permite
saltar al veredicto. Cada escenario dura menos de un minuto a 1×.

| Escenario | Servidor | Qué muestra |
|---|---|---|
| Aprobado | `filesystem-mcp` | Los cuatro agentes pasan; Seguro, 88 |
| Bloqueo de Vigil | `weather-mcp` | Tool poisoning en `tools/list`: DeBERTa y YARA coinciden, la tubería se corta, Malicioso, 0 |
| Exfiltración | `issues-sync-mcp` | La sonda descubre un webhook externo; Occludra enmascara emails y tokens; No confiable, 23 |
| Degradado | `notes-mcp` | El fuzzer no responde; el run sigue con tres agentes; Precaución, 61 |

`calendar-mcp` corre de fondo y vuelve a empezar solo, como si lo disparara su
cron.

## Vistas

Cada vista es una grilla Bento de 12 columnas: el tamaño de cada mosaico
marca su importancia y el veredicto es el único mosaico de color sólido.

- **Flujo del prompt.** Cada llamada al modelo recorre las estaciones Servidor
  MCP → Vigil → Prompt → Occludra → NetBird → Modelo → Agente → Síntesis →
  Veredicto. Al hacer click en una estación se ve su detalle.
- **Ciclo de vida.** Las fases del `MCPEvaluationRun` y un carril por agente,
  sobre un eje de tiempo común.
- **Servidores.** Columnas En evaluación, Aprobados y Rechazados. El detalle
  incluye spec, veredicto, hallazgos e historial.
- **Terminal.** El log del contenedor `evaluator`, en solo lectura.

## Cómo se arma

```
src/model/       tipos espejo de api/v1alpha1 y del report del runner;
                 flow.ts reconstruye cada llamada a partir de los logs
src/data/        DataSource: DemoSource (replay) y LiveSource (WebSocket)
src/views/       las cuatro vistas
server/live.ts   backend live: watch de CRs, ConfigMap del report, logs del evaluator
test/            vitest + API server falso
deploy/          Deployment opcional para el cluster (ver abajo)
```

Demo y live producen los mismos objetos: CRs con la forma de los CRDs, líneas
de log con el formato de `runner/src/logger.ts` y el `EvaluationReport` del
ConfigMap `<run>-report`. El flujo del prompt se deriva igual en los dos modos
(`deriveTrips` en `src/model/flow.ts`).

## Qué sale del cluster y qué no

- El backend usa permisos de solo lectura: `get/list/watch` de los tres CRDs,
  `get` de ConfigMaps, `get/list` de pods y `get` de `pods/log`. No tiene
  `pods/exec` ni acceso a Secrets.
- La terminal no tiene stdin. Solo muestra el contenedor `evaluator`; los
  logs de `target` (el servidor no confiable) y de `cloner` nunca se leen.
- El runner enmascara prompts, payloads y credenciales antes de escribir cada
  línea, así que la terminal no expone evidencia.

## Supuestos sobre los datos

- **Votos de Vigil por escáner.** Están en el report, que existe recién al
  terminar el run. Mientras corre, el live solo sabe lo que dicen los logs:
  cuántos textos se escanearon, cuántas advertencias hubo y, si hay bloqueo,
  qué escáneres coincidieron y con qué confianza.
- **Redacciones de Occludra.** Occludra nunca registra el contenido. En live
  solo hay conteos por detector, de todo el gateway, si se configura
  `PROM_URL`. Los ejemplos enmascarados (`a***@e***.com`) y las latencias por
  estación existen solo en la demo, y la UI lo indica.
- **Tiempos por fase.** El CR solo guarda `startTime` y `completionTime`. La UI
  anota cuándo vio cada fase; en un run que ya había pasado una fase al
  conectarse, esa fase no muestra hora.
- **Logs en live.** Los logs existen mientras exista el pod: el Job se borra 10
  minutos después de terminar (`ttlSecondsAfterFinished: 600`). Los runs
  viejos muestran veredicto y report, pero no el flujo.
- **Sesión de OpenCode.** La sesión interna (`127.0.0.1:4096` dentro del pod)
  no se expone, a propósito. Lo que se ve es el log del evaluator, que es
  quien la maneja.
- **Repositorios de la demo.** Son ficticios, salvo `filesystem-mcp`, que es el
  sample del repo.

## Desplegarlo en el cluster (opcional)

```bash
docker build -t $IMG_REGISTRY/mcp-eval-ui:$TAG frontend && docker push $IMG_REGISTRY/mcp-eval-ui:$TAG
sed "s|ghcr.io/security-eval/mcp-eval-ui:latest|$IMG_REGISTRY/mcp-eval-ui:$TAG|" frontend/deploy/mcp-eval-ui.yaml | kubectl apply -f -
kubectl -n mcp-eval-ui port-forward svc/mcp-eval-ui 8787:80     # http://localhost:8787/?mode=live
```

El manifest crea el namespace `mcp-eval-ui` (PodSecurity `restricted`), un
Role de solo lectura en `mcp-evals`, el Deployment (no-root, filesystem raíz
de solo lectura) y una NetworkPolicy sin ingress, con salida solo a DNS, al
API server y a Prometheus. Para que lleguen los conteos de Occludra, la
NetworkPolicy `observability-isolation` tiene que aceptar tráfico desde
`mcp-eval-ui` al puerto 9090; hoy solo acepta pods de su propio namespace.

`deploy.sh` no lo instala todavía.

## Desarrollo

```bash
npm run typecheck
npm test
npm run build && NODE_ENV=production npm start   # sirve dist/ y el WebSocket en :8787
```
