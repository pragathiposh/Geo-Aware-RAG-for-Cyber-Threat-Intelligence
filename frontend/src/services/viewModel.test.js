import test from "node:test";
import assert from "node:assert/strict";
import { buildDashboardView } from "./viewModel.js";

test("dashboard view preserves geo evidence roles and separates country associations", () => {
  const view = buildDashboardView({
    geographic_findings: {
      supported_location_evidence: [{ country: "India", role: "victim_location", status: "supported", evidence_text: "Victims in India" }],
      aggregation: { evidence_supported_counts: { India: { count: 1 } }, source_association_counts: { India: 4 } },
    },
    sources: [{ countries: ["India"], attack_ids: ["T1486"], geographic_evidence: [] }],
  });
  assert.equal(view.geographic.evidence[0].role, "victim_location");
  assert.equal(view.geographic.evidenceCounts.India.count, 1);
  assert.equal(view.geographic.sourceAssociationCounts.India, 4);
  assert.deepEqual(view.sources[0].attack_ids, ["T1486"]);
});

test("dashboard view prepares correlation, priority, source, trace and partial states", () => {
  const view = buildDashboardView({
    partial: true,
    threat_correlations: [{ source_record_id: "a", related_record_id: "b" }],
    contextual_priorities: [{ source_record_id: "a", contextual_priority_score: 52, factors: [{ factor: "recency" }] }],
    sources: [{ source_record_id: "a", chunk_id: "a-1", malware_families: "LockBit", countries: "India" }],
    execution_trace: { entries: [{ agent_name: "correlation", status: "partial" }] },
    agent_results: { geographic: { missing_information: ["No supported location."] } },
  });
  assert.equal(view.partial, true);
  assert.equal(view.relationships[0].related_record_id, "b");
  assert.equal(view.priorities[0].contextual_priority_score, 52);
  assert.deepEqual(view.sources[0].malware_families, ["LockBit"]);
  assert.deepEqual(view.sources[0].countries, ["India"]);
  assert.equal(view.trace[0].agent_name, "correlation");
  assert.ok(view.warnings.includes("No supported location."));
});

test("empty and legacy responses produce safe empty dashboard sections", () => {
  const view = buildDashboardView({ query: "old", answer: "legacy answer", sources: [] });
  assert.equal(view.answer, "legacy answer");
  assert.equal(view.sources.length, 0);
  assert.equal(view.geographic.evidence.length, 0);
  assert.equal(view.relationships.length, 0);
  assert.equal(view.priorities.length, 0);
  assert.equal(view.trace.length, 0);
});
