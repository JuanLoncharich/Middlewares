// Hash routes, so the static server needs no rewrites and links survive a reload:
//   #/                              servers
//   #/servidores/<server>[/<run>]   one server, its latest (or a given) run
//   #/como-funciona                 how the platform works, with the live path demo
import { useEffect, useState } from "react";

export type Route =
  | { page: "servers" }
  | { page: "server"; server: string; run: string | null }
  | { page: "how" };

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (parts[0] === "servidores" && parts[1]) return { page: "server", server: parts[1], run: parts[2] ?? null };
  if (parts[0] === "como-funciona") return { page: "how" };
  return { page: "servers" };
}

export function href(route: Route): string {
  switch (route.page) {
    case "server":
      return `#/servidores/${encodeURIComponent(route.server)}${route.run ? `/${encodeURIComponent(route.run)}` : ""}`;
    case "how":
      return "#/como-funciona";
    default:
      return "#/";
  }
}

export function go(route: Route): void {
  location.hash = href(route);
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseRoute(location.hash));
  useEffect(() => {
    const onChange = () => {
      setRoute(parseRoute(location.hash));
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
