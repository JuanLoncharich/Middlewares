/** Vigil's three scanners, by the names its /analyze/prompt answer uses. */
export const SCANNERS = [
  { id: "scanner:transformer", name: "DeBERTa", what: "Clasificador de prompt injection" },
  { id: "scanner:yara", name: "YARA", what: "Reglas de patrones" },
  { id: "scanner:vectordb", name: "Chroma", what: "Similitud con 40 000 ataques conocidos" },
];
