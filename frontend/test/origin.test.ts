import { describe, expect, it } from "vitest";
import { isSameOrigin } from "../server/origin.ts";

describe("isSameOrigin", () => {
  it("accepts the page's own origin", () => {
    expect(isSameOrigin("http://localhost:8787", "localhost:8787")).toBe(true);
    expect(isSameOrigin("http://localhost:5173", "localhost:5173")).toBe(true);
  });
  it("accepts clients that send no Origin (not a browser)", () => {
    expect(isSameOrigin(undefined, "localhost:8787")).toBe(true);
  });
  it("rejects any other site", () => {
    expect(isSameOrigin("https://evil.example", "localhost:8787")).toBe(false);
    expect(isSameOrigin("http://localhost:5173", "localhost:8787")).toBe(false);
    expect(isSameOrigin("null", "localhost:8787")).toBe(false);
    expect(isSameOrigin("http://localhost:8787", undefined)).toBe(false);
  });
});
