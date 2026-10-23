// Same-origin check for the WebSocket upgrade. Browsers send any page's
// Origin on a WebSocket handshake and never apply CORS to it, so without this
// any site open in the browser could connect to a local `npm run live` (which
// runs with the developer's kubeconfig) and read every run, report and
// evaluator log. Clients outside a browser send no Origin and are allowed.
// The vite dev proxy keeps Host and Origin both on the vite port, so dev mode
// passes as same-origin too.
export function isSameOrigin(origin: string | undefined, host: string | undefined): boolean {
  if (origin === undefined) return true;
  if (!host) return false;
  try {
    return new URL(origin).host === host.toLowerCase();
  } catch {
    return false;
  }
}
