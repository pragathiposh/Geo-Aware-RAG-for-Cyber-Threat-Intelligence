import test from "node:test";
import assert from "node:assert/strict";
import { getApiBaseUrl, queryCTI } from "./api.js";

test("API URL comes from runtime configuration and is normalized", () => {
  assert.equal(getApiBaseUrl({ apiBaseUrl: "http://127.0.0.1:8000/" }), "http://127.0.0.1:8000");
  assert.throws(() => getApiBaseUrl({}), /not configured/);
  assert.throws(() => getApiBaseUrl({ apiBaseUrl: "file:///tmp" }), /invalid/);
});

test("query submits the expected request and parses the complete response", async () => {
  let captured;
  const payload = { query: "  ransomware? ", answer: "answer", sources: [], execution_trace: { entries: [] } };
  const result = await queryCTI("  ransomware? ", {
    baseUrl: "http://api.test",
    fetchImpl: async (url, options) => {
      captured = { url, options };
      return { ok: true, json: async () => payload };
    },
  });
  assert.equal(captured.url, "http://api.test/query");
  assert.equal(captured.options.method, "POST");
  assert.deepEqual(JSON.parse(captured.options.body), { query: "ransomware?" });
  assert.equal(result.execution_trace.entries.length, 0);
});

test("query reports sanitized API and network failures", async () => {
  await assert.rejects(queryCTI("test", { baseUrl: "http://api.test", fetchImpl: async () => { throw new Error("secret stack"); } }), /Could not reach/);
  await assert.rejects(queryCTI("test", { baseUrl: "http://api.test", fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({ detail: { error: { message: "Safe public error" } } }) }) }), /Safe public error/);
  await assert.rejects(queryCTI("   ", { baseUrl: "http://api.test" }), /Enter a CTI question/);
});
