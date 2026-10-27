# mcp-eval-ui

La interfaz de la plataforma: agregás el repositorio de un servidor MCP, la
plataforma lo evalúa en una caja aislada y te dice, en lenguaje llano, si es
seguro conectarlo a un agente de IA y por qué. Funciona con el cluster (modo
Cluster, el de siempre cuando está desplegada) o con datos de demostración
(modo Demo, el de `npm run demo`). El selector está abajo a la izquierda.

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

El selector Claro/Oscuro de la barra lateral cambia el tema y lo recuerda en
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

## Pantallas

- **Servidores** (`#/`). La lista, con el veredicto de cada uno, cuándo se
  evaluó y cada cuánto se repite. "Evaluar un servidor" abre el formulario:
  repositorio, nombre (se completa solo), rama, carpeta, cómo se conecta
  (stdio o SSE) y frecuencia. Al guardarlo se crea el `MCPServer` y la primera
  evaluación arranca enseguida.
- **Un servidor** (`#/servidores/<nombre>[/<run>]`). El sello con el
  veredicto, el historial de evaluaciones y dos pestañas: "Qué pasó" (cada
  paso del análisis en lenguaje llano, con el detalle técnico desplegable, y
  qué habría que arreglar) y "Registro técnico" (el log del evaluador). A la
  derecha, "Preguntale al análisis": un chat cuyo modelo tiene delante los
  resultados de esa evaluación. Acciones: evaluar ahora, pausar o reanudar y
  borrar. Los servidores que vienen de git (Flux) se pueden evaluar, pero no
  pausar ni borrar desde acá: Flux los volvería a poner.
- **Cómo funciona** (`#/como-funciona`). Las cinco piezas de la plataforma y
  "Probá el camino hasta el modelo": un chat que muestra por dónde pasa cada
  respuesta y qué tapa Occludra.

La historia de cada análisis sale de `buildStory` (`src/model/story.ts`):
primero la respuesta estructurada de cada agente en `status.agentResults`
(vive con el CR, así que sirve también para runs viejos), después el report y,
mientras el Job existe, los logs.

## Cómo se arma

```
src/model/       tipos espejo de api/v1alpha1 y del report del runner;
                 flow.ts reconstruye cada llamada a partir de los logs;
                 story.ts arma la historia del run en lenguaje llano
src/data/        DataSource: DemoSource (replay) y LiveSource (WebSocket)
src/views/       las vistas; AnalysisView es la principal
server/live.ts   backend live: watch de CRs, ConfigMap del report, logs del evaluator
test/            vitest + API server falso
deploy/          Deployment opcional para el cluster (ver abajo)
```

Demo y live producen los mismos objetos: CRs con la forma de los CRDs, líneas
de log con el formato de `runner/src/logger.ts` y el `EvaluationReport` del
ConfigMap `<run>-report`. El flujo del prompt se deriva igual en los dos modos
(`deriveTrips` en `src/model/flow.ts`).

## Qué sale del cluster y qué no

- El backend lee: `get/list/watch` de los tres CRDs, `get` de ConfigMaps,
  `get/list` de pods y `get` de `pods/log`. Escribe solo `MCPServer` en
  `mcp-evals` (`create`, `patch`, `delete`), para el formulario y las acciones
  (`server/actions.ts`). No tiene `pods/exec` ni acceso a Secrets.
- Rutas que escriben: `POST /api/servers` (crear), `POST
  /api/servers/<n>/evaluate`, `POST /api/servers/<n>/pause` y `DELETE
  /api/servers/<n>`, más `POST /api/chat`. Todas exigen un `Origin` igual al
  `Host`: el navegador manda la contraseña de Traefik a cualquier sitio que
  apunte acá, y sin ese chequeo otra página podría actuar en tu nombre.
- El formulario valida en el navegador y otra vez en el servidor
  (`src/model/serverForm.ts`): solo repositorios `https://`, nombres DNS de
  hasta 40 caracteres, carpetas sin `..`, y como mucho 20 servidores creados
  desde la UI.
- La terminal no tiene stdin. Solo muestra el contenedor `evaluator`; los
  logs de `target` (el servidor no confiable) y de `cloner` nunca se leen.
- El runner enmascara prompts, payloads y credenciales antes de escribir cada
  línea, así que la terminal no expone evidencia.

## Los chats

Los dos usan el mismo camino que los agentes: servidor de la UI → OpenCode →
Occludra (qué tapó) → la PC por ZeroTier → LFM en la GPU → vuelta.

- **Preguntale al análisis** manda `run` en `POST /api/chat`. La primera
  pregunta de cada sesión lleva los datos de esa evaluación
  (`src/model/askContext.ts`): veredicto, hallazgos, detecciones de Vigil y la
  respuesta de cada agente, recortados para entrar en 32K tokens. El texto que
  viene del servidor evaluado va entre `<datos>` y marcado como datos, no
  instrucciones; como el modelo no tiene herramientas, lo peor que puede hacer
  un texto envenenado es confundir una respuesta.
- **Probá el camino** (en Cómo funciona) es el chat sin contexto, para ver el
  recorrido.

- `frontend/deploy/ui-chat.yaml`: un Deployment `opencode-chat` (imagen del
  runner, `opencode serve`) con todas las herramientas denegadas, sin token de
  ServiceAccount, no-root y con filesystem de solo lectura. Su único proveedor
  es Occludra (`occludra-service:8080`), con el header
  `X-Occludra-Client: ui-chat`. `deploy.sh` arma la configuración con
  `LLM_PROVIDER`/`LLM_MODEL`; `DEPLOY_UI_CHAT=0` lo deja afuera.
- Occludra anota esas llamadas en su registro (`journal.go`): solo cuentas por
  detector, estado, tiempos y tamaños, nunca el texto. La UI lo lee en el
  puerto 8081, que solo está abierto para el pod de la UI.
- `server/chat.ts` atiende de a una pregunta por vez (el modelo es una sola
  GPU) y devuelve la respuesta con las llamadas que vio Occludra.
- En modo demo el chat está desactivado: usa el modelo de verdad.

Para probarlo con `npm run live`, apuntá `CHAT_URL` a un OpenCode y
`OCCLUDRA_INSPECT_URL` al registro de Occludra, por ejemplo con
`kubectl -n mcp-eval-ui port-forward svc/opencode-chat 4096` y
`kubectl -n security-gateways port-forward svc/occludra-service 8081`.

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
- **Sesión de OpenCode de las evaluaciones.** La sesión interna
  (`127.0.0.1:4096` dentro del pod de evaluación) no se expone, a propósito:
  ese pod corre el servidor no confiable. El chat usa otro OpenCode, aparte.
- **Repositorios de la demo.** Son ficticios, salvo `filesystem-mcp`, que es el
  sample del repo.

## Desplegarlo en el cluster

La imagen la construye CI (`.github/workflows/images.yml`) en cada push a
`main`: `docker.io/jjhonson/mcp-eval-ui:sha-<commit>`, nunca `:latest`.
`deploy.sh` la instala con `DEPLOY_UI=1`, que está activado para el cluster
k0s (`deploy/k0s/render.env`), así que Flux la despliega sola. Para verla:

```bash
kubectl -n mcp-eval-ui port-forward svc/mcp-eval-ui 8787:80     # http://localhost:8787/?mode=live
```

En otro cluster: `DEPLOY_UI=1 IMG_REGISTRY=... ./deploy.sh` (construye,
pushea y aplica), o solo la imagen y el manifest:

```bash
docker build -t $IMG_REGISTRY/mcp-eval-ui:$TAG frontend && docker push $IMG_REGISTRY/mcp-eval-ui:$TAG
sed "s|__UI_IMG__|$IMG_REGISTRY/mcp-eval-ui:$TAG|" frontend/deploy/mcp-eval-ui.yaml | kubectl apply -f -
```

El manifest crea el namespace `mcp-eval-ui` (PodSecurity `restricted`), un
Role de solo lectura en `mcp-evals`, el Deployment (no-root, filesystem raíz
de solo lectura) y una NetworkPolicy sin ingress, con salida solo a DNS y a
Prometheus. La salida al API server es otra NetworkPolicy
(`mcp-eval-ui-kube-api`) que `deploy.sh` genera con la IP y el puerto reales
del API server de cada cluster: Calico evalúa la política después del DNAT
del Service `kubernetes`, así que hay que nombrar el endpoint real, no
`kubernetes.default`. Sin `deploy.sh`, creala a mano con la salida de
`kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes`.

Para que lleguen los conteos de Occludra, la NetworkPolicy
`observability-isolation` tiene que aceptar tráfico desde `mcp-eval-ui` al
puerto 9090; hoy solo acepta pods de su propio namespace.

El WebSocket (`/api/stream`) solo acepta conexiones cuyo `Origin` sea el de la
propia página (o sin `Origin`, fuera de un navegador): así ninguna otra web
abierta en el navegador puede leer los runs a través de un `npm run live`
local o de un port-forward.

## Desarrollo

```bash
npm run typecheck
npm test
npm run build && NODE_ENV=production npm start   # sirve dist/ y el WebSocket en :8787
```
