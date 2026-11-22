import { queryCTI } from "./services/api.js";
import { buildDashboardView } from "./services/viewModel.js";

const $ = (selector) => document.querySelector(selector);
const form = $("#query-form");
const input = $("#query-input");
const button = $("#submit-button");
const requestState = $("#request-state");
const results = $("#results");
const emptyState = $("#empty-state");

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) { node.replaceChildren(); }
function metadataValues(values, className = "meta-chip") {
  return values.filter((value) => value !== "" && value !== null && value !== undefined).map((value) => element("span", className, typeof value === "object" ? value.name ?? value.value ?? JSON.stringify(value) : value));
}

function renderGeography(model) {
  const root = $("#geo-content"); clear(root);
  const evidence = model.geographic.evidence;
  const evidenceEntries = Object.entries(model.geographic.evidenceCounts);
  if (!evidence.length && !evidenceEntries.length) {
    root.append(element("p", "empty-copy", "No supported incident, target, or victim location evidence was found in the retrieved reports."));
  } else {
    const wrap = element("div", "table-wrap");
    const table = element("table");
    const head = element("thead"); const row = element("tr");
    ["LOCATION", "SUPPORTED ROLE", "SOURCE RECORD", "EVIDENCE"].forEach((label) => row.append(element("th", "", label)));
    head.append(row); table.append(head);
    const body = element("tbody");
    for (const claim of evidence) {
      const tr = element("tr");
      tr.append(element("td", "", claim.country ?? claim.region ?? "Location unspecified"));
      const role = element("td"); role.append(element("span", `role-pill ${claim.role ?? "mention"}`, claim.role ?? "Unclassified")); tr.append(role);
      tr.append(element("td", "", claim.source_record_id ?? "Unknown"));
      const text = element("td"); text.append(element("span", "", claim.evidence_text ?? "Evidence text unavailable"));
      const status = claim.status ?? "unknown";
      text.append(element("small", "", `${claim.extraction_method ?? "Extraction method unavailable"} · ${status}`)); tr.append(text);
      body.append(tr);
    }
    table.append(body); wrap.append(table); root.append(wrap);
    if (!evidence.length) root.append(element("p", "empty-copy", `${evidenceEntries.length} aggregate group(s) were returned, but no evidence detail was attached.`));
  }
  if (evidenceEntries.length) {
    const label = element("p", "empty-copy", "Distinct source-record counts by supported geography:");
    label.style.marginTop = "12px"; root.append(label);
    const chips = element("div", "source-meta");
    for (const [place, details] of evidenceEntries) {
      const count = typeof details === "object" ? details.count : details;
      chips.append(element("span", "meta-chip", `${place} · ${count} supported source record(s)`));
    }
    root.append(chips);
  }
  const assoc = Object.entries(model.geographic.sourceAssociationCounts);
  if (assoc.length) {
    const label = element("p", "empty-copy", "Source-associated country metadata (not confirmed incident geography):");
    label.style.marginTop = "14px"; root.append(label);
    const chips = element("div", "source-meta");
    for (const [country, count] of assoc) chips.append(element("span", "meta-chip", `${country} · ${count} source record(s)`));
    root.append(chips);
  }
}

function renderCorrelations(model) {
  const root = $("#correlation-content"); clear(root);
  if (!model.relationships.length) {
    root.append(element("p", "empty-copy", "No sufficiently supported relationships were found in the retrieved records. Shared generic techniques alone are not treated as proof of a relationship.")); return;
  }
  for (const relation of model.relationships) {
    const item = element("div", "finding");
    const ids = [relation.source_record_id, relation.related_record_id].filter(Boolean).join(" ↔ ");
    const header = element("div", "finding-head"); header.append(element("span", "finding-title", ids || "Related source records"));
    if (relation.correlation_confidence !== undefined) header.append(element("span", "score", `${Math.round(relation.correlation_confidence * 100)}% evidence score`));
    item.append(header);
    const entities = (relation.matched_entities ?? []).map((entry) => `${entry.entity_type}: ${entry.normalized_value}`).join(" · ");
    item.append(element("p", "", [relation.explanation, entities, (relation.relationship_types ?? []).join(", ")].filter(Boolean).join(" — ")));
    for (const ev of (relation.supporting_evidence ?? []).slice(0, 3)) item.append(element("p", "", `${ev.source_record_id}: ${ev.text ?? ""}`));
    root.append(item);
  }
  root.append(element("p", "empty-copy", "Relationship strength is an uncalibrated evidence heuristic, not proof of a shared campaign."));
}

function renderPriorities(model) {
  const root = $("#priority-content"); clear(root);
  if (!model.priorities.length) {
    root.append(element("p", "empty-copy", "No canonical records were available for contextual prioritization.")); return;
  }
  for (const item of model.priorities) {
    const card = element("div", "finding");
    const head = element("div", "finding-head"); head.append(element("span", "finding-title", item.source_record_id ?? "Source record"));
    head.append(element("span", "score", item.contextual_priority_score == null ? "Unknown" : `${Number(item.contextual_priority_score).toFixed(1)} / 100`)); card.append(head);
    card.append(element("p", "", item.explanation ?? "No score explanation was provided."));
    card.append(element("p", "empty-copy", `Evidence coverage: ${Math.round((item.coverage ?? 0) * 100)}% · contextual review ordering only; not a probability or prediction.`));
    const factors = element("ul", "factor-list");
    for (const factor of item.factors ?? []) {
      const line = element("li");
      line.append(element("span", "", `${factor.factor} · ${factor.status}${factor.rationale ? ` · ${factor.rationale}` : ""}`));
      line.append(element("span", "", factor.normalized_contribution == null ? "—" : Number(factor.normalized_contribution).toFixed(3)));
      factors.append(line);
    }
    card.append(factors);
    if ((item.missing_factors ?? []).length) card.append(element("p", "empty-copy", `Missing factors: ${item.missing_factors.join(", ")}`));
    root.append(card);
  }
}

function renderSources(model) {
  const root = $("#sources-content"); clear(root);
  $("#source-count").textContent = `${model.sources.length} SOURCE${model.sources.length === 1 ? "" : "S"}`;
  if (!model.sources.length) { root.append(element("article", "panel empty-copy", "No source documents were retrieved for this query.")); return; }
  for (const source of model.sources) {
    const card = element("article", "source-card");
    const header = element("div", "source-header"); header.append(element("span", "source-rank", `S${source.rank}`));
    const title = element("div"); title.append(element("div", "source-title", source.title || "Untitled CTI report"));
    title.append(element("div", "source-id", `${source.source_record_id ?? "Unknown source"} · chunk ${source.chunk_id ?? "unknown"}`)); header.append(title);
    header.append(element("span", "source-score", `RELEVANCE ${Number(source.similarity_score ?? 0).toFixed(3)}`)); card.append(header);
    card.append(element("p", "source-excerpt", source.excerpt || "No excerpt available."));
    const chips = element("div", "source-meta");
    chips.append(...metadataValues(source.attack_ids, "meta-chip attack-chip"));
    chips.append(...metadataValues(source.attack_techniques.map((technique) => {
      const id = technique.attack_id ?? technique.id;
      const name = technique.name ?? technique.technique_name;
      return [id, name].filter(Boolean).join(" — ");
    }), "meta-chip attack-chip"));
    chips.append(...metadataValues(source.malware_families)); chips.append(...metadataValues(source.industries));
    if (chips.childNodes.length) card.append(chips);
    if (source.countries.length) {
      const countries = element("p", "source-geo", `Source-associated countries: ${source.countries.join(", ")} · not incident-location evidence`); card.append(countries);
    }
    for (const geo of source.geographic_evidence) {
      card.append(element("p", "source-geo", `${geo.role ?? "Geographic mention"} (${geo.status ?? "unknown"}): ${geo.evidence_text ?? ""}`));
    }
    root.append(card);
  }
}

function renderTrace(model) {
  const root = $("#trace-content"); clear(root);
  if (!model.trace.length) { root.append(element("p", "empty-copy", "No execution trace was returned.")); return; }
  for (const entry of model.trace) {
    const row = element("div", "trace-row");
    row.append(element("span", "trace-name", entry.agent_name ?? "Agent"));
    row.append(element("span", "", entry.selected ? "SELECTED" : "NOT SELECTED"));
    row.append(element("span", `status-pill ${entry.status ?? "unknown"}`, entry.status ?? "unknown"));
    row.append(element("span", "", `${entry.reason ?? ""}${entry.warnings?.length ? ` · ${entry.warnings.join("; ")}` : ""}${entry.error ? ` · ${entry.error}` : ""}`));
    row.append(element("span", "", `${Number(entry.execution_duration_ms ?? 0).toFixed(1)} ms`)); root.append(row);
  }
}

function render(response) {
  const model = buildDashboardView(response);
  $("#answer-text").textContent = model.answer;
  const caveats = model.warnings;
  $("#answer-caveats").textContent = caveats.length ? `Evidence gaps: ${caveats.join(" · ")}` : "Interpret findings within the limits of the retrieved reports and their provenance.";
  $("#partial-badge").classList.toggle("hidden", !model.partial);
  renderGeography(model); renderCorrelations(model); renderPriorities(model); renderSources(model); renderTrace(model);
  const warningPanel = $("#warnings-panel");
  warningPanel.classList.toggle("hidden", !model.warnings.length);
  const warningList = $("#warnings-content"); clear(warningList);
  model.warnings.forEach((warning) => warningList.append(element("li", "", warning)));
  $("#results").classList.remove("hidden"); emptyState.classList.add("hidden");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = input.value.trim();
  if (!query) { requestState.textContent = "Enter a CTI question before submitting."; input.focus(); return; }
  button.disabled = true; button.querySelector(".button-label").textContent = "ANALYZING…";
  requestState.textContent = "Retrieving reports and running selected analyses…";
  try {
    const payload = await queryCTI(query);
    render(payload);
    requestState.textContent = "Analysis complete. Review the source evidence and uncertainty alongside the answer.";
  } catch (error) {
    requestState.textContent = error instanceof Error ? error.message : "The query could not be completed.";
  } finally {
    button.disabled = false; button.querySelector(".button-label").textContent = "ANALYZE QUERY";
  }
});

if (!globalThis.GEORAG_CONFIG?.apiBaseUrl) {
  requestState.textContent = "API address is not configured. Start the frontend with GEORAG_API_URL set; see frontend/README.md.";
}
