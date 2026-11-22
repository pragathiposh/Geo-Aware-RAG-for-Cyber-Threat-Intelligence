# GeoRAG-CTI — Codex Project Handoff

**Project:** Geo-Aware Retrieval-Augmented Generation for Cyber Threat Intelligence (GeoRAG-CTI)
**Environment last reported:** Windows PowerShell, Python 3.12.6, virtual environment at repository root `.venv`, FastAPI backend under `backend/`.
**Status:** Phases 1–5 are complete. Phase 6 API/dashboard implementation and automated checks are in place; runtime validation remains open because Qwen loaded but generation exceeded the configured timeout, and browser query integration is unverified. Do not start Phase 7 until that gate and review are complete. Preserve the current checkout and pre-existing changes.

## What this project must do

Provide evidence-grounded cyber threat intelligence (CTI) retrieval, geographic analysis, ATT&CK enrichment, contextual risk prioritization, and visualization. Geography means locations **supported by incident/report evidence**; do not infer that a country in a generic metadata field is the actual attack location or attacker origin. Distinguish target/victim/incident, infrastructure, actor origin, and mere mentions. Risk scoring is evidence-based **contextual prioritization**, not a prediction of future attacks. Current data source is a **downloaded/local OTX CSV**, not a live feed. Architecture is **modular and centrally orchestrated**, not autonomous agents.

## Known application architecture (from prior inspection; re-verify in current repo)

- `backend/app/main.py`: FastAPI `/health`, `/ready`, and `/query`. Pipeline/model construction is lazy and occurs once on first query. `/query` preserves `{query, answer, sources}` and returns typed findings, plan, agent results, trace, warnings, and missing evidence. Exceptions and nested diagnostics are sanitized for API clients; details are server-logged only.
- `backend/app/rag/pipeline.py`: compatibility facade over the central Phase 5 orchestrator. Production construction uses one `CTIHybridRetriever` with weighted fusion as default, one Qwen generator and one prompt builder. Existing query result keys remain present, with plan, agent results, execution trace and warnings added for direct pipeline callers.
- `backend/app/rag/retriever.py`: MiniLM embeddings and FAISS semantic search. `retrieve_semantic` returns raw candidates; `retrieve` deduplicates by stable chunk ID so sibling chunks survive.
- `backend/app/rag/hybrid_retriever.py`: FAISS + BM25 supports configurable weighted (default) and weighted Reciprocal Rank Fusion, keyed by chunk IDs; filters candidates before a bounded cross-encoder pool. Phase 5 pipeline and Phase 6 API use this hybrid retriever.
- `backend/app/rag/reranker.py`: `cross-encoder/ms-marco-MiniLM-L-6-v2`; input pairs are token-budgeted (512 tokens by default) while retaining a metadata header and document evidence. Scores remain raw relevance logits, not probabilities.
- `backend/app/rag/query_parser.py` + `filter_builder.py`: parse threat type/country/region/industry/malware/ATT&CK; filter builder constructs metadata filters but **not threat_type** (metadata lacks it). `geo_resolver.py` is partial (North America mapping excludes Mexico in prior version).
- `backend/app/rag/metadata_filter.py`: country filtering uses exact normalized equality and aliases from the existing CTI normalizer. Other metadata keeps containment matching. Country values remain source associations, not incident-location or origin claims.
- `backend/app/rag/prompt.py`: grounded-evidence instructions and relevance-score semantics. Phase 5 appends a source registry and checks for at least one valid source label, falling back to evidence excerpts if the model returns no valid citation.
- `backend/app/rag/generator.py`: local Qwen 1.5B; `do_sample=True`, temperature=.2, top_p=.9; tokenizer truncates to 4096 tokens, no explicit token budget/citation verification; inference may be heavy on CPU.
- `backend/app/rag/loader.py`: pandas loads `data/raw/csv/1_otx_threat_intel.csv` (~2365 rows), builds LangChain Documents and metadata; tags missing from metadata in past version, possible textual `nan`, country association not incident evidence.
- `backend/app/preprocessing/cleaner.py`, `splitter.py`: whitespace cleanup; 800-char chunks / 120 overlap, metadata copied.
- `backend/app/threat_analysis/cti_schema.py`, `cti_mapper.py`, `normalization.py`, `attack_enricher.py`: canonical CTI mapping, normalization, and ATT&CK enrichment are implemented separately, but were **not called by** `backend/build_vector_store.py` in previously reviewed version. Active and historical ATT&CK enrichment tests reportedly passed after a compatibility fix.
- `backend/build_vector_store.py`: canonical loader/ATT&CK enrichment -> cleaner -> splitter -> MiniLM -> FAISS save; defaults to `data/vector_store_phase1` and refuses an existing output directory. Runtime app, API, chat, retriever, and smoke-test defaults now also select Phase 1; `GEORAG_VECTOR_STORE_PATH` and smoke `--vector-store` remain explicit overrides. Some legacy demos/tests intentionally retain explicit original-index paths.
- `backend/download_mitre_attack.py`: standard-library bootstrap for pinned MITRE/CTI ATT&CK-v20.1 STIX 2.0; validates before atomic replacement and writes a download manifest. Run it before building a fresh vector store.
- `backend/app/vector_db/faiss_store.py`: FAISS IndexFlatIP on L2-normalized 384-d embeddings (cosine-like). `documents.pkl` stored with pickle — use only trusted files, never unpickle arbitrary input. Persistence and count validation exist.
- `backend/requirements.txt`: declares `rank-bm25==0.2.2` for BM25 retrieval.

## Dataset/index caveats

The Phase 1 reference index `backend/data/vector_store_phase1` contains 2,820 vectors/documents at 384 dimensions and is read-only during Phase 2. The original `backend/data/vector_store` had 100 vectors when inspected at Phase 1. Do not infer attack geolocation from generic CSV `Countries` alone.

## Known previous testing

Past tests were reported passing for schema/normalization/dataset mapping/ATT&CK enrichment, embeddings, FAISS load, BM25, and hybrid retrieval, including a North America test with four filtered candidates. These are **previous-session observations, not evidence that the current checkout passes**. New Phase 1 patch ZIP was offered in chat, but application to the Windows checkout and complete validation are unconfirmed. If a patch ZIP exists in repo, inspect/diff it before applying; do not trust blindly.

## Required implementation order

Phases 1–5 are complete and recorded below. Phase 6 is in progress; Phase 7 has not started:

1. **Phase 5 — Central orchestration:** complete (see Phase 5 record below).
2. **Phase 6 — Complete application integration (implementation complete;
   mandatory local-model runtime gate open):** validate actual inference with
   cached embedding/reranker/Qwen models after resolving the workstation memory
   limit. Do not mark complete while this gate is open.
3. **Phase 7 — Evaluation and finalization (not started):** end-to-end tests, gold query set,
   retrieval and geographic evaluation, citation/grounding checks, latency,
   security review, and reproducible documentation.

## Engineering rules

- Work in the **actual repository**. Read and verify code before edits. Run small tests after each change and report output and failures truthfully.
- Create a feature branch or backup before editing, if repo state permits. Preserve user changes, dataset, existing vector store and downloaded models; never run destructive commands or overwrite indices without approval.
- Favor minimal changes that maintain current FastAPI response compatibility and existing APIs. Keep tests close to source.
- Avoid inventing CTI observations, incident locations, model performance, or test results. Clearly separate geographic *association* metadata from evidenced incident/victim locations.
- Do not integrate all phases in one unreviewed pass. Implement sequentially with verification after each phase.
- Use Windows-compatible commands and the existing virtualenv; avoid needless installations or rebuilding large models if not required.
- Record meaningful decisions in this handoff/README as phases are completed so the next Codex session can resume.

## Codex first assignment

1. Read this file, `README*`, `backend/app/`, `backend/build_vector_store.py`, existing tests, `requirements.txt`, and check git status. Show concise findings confirming/correcting the handoff.
2. Run **read-only** safe checks and appropriate existing tests, noting failures.
3. Implement **Phase 1 only** in small, testable commits/edits. First ensure reliable canonical ingestion, normalization, metadata and source provenance. Add regression tests. Do not overwrite `backend/data/vector_store`.
4. Report changed files, tests run/results, any unresolved blockers, and precise next phase action.

## Current Codex session progress (2026-11-14)

Phase 1 implementation changes in this checkout:

- `load_cti_csv` sanitizes null-like CSV values and records source file, row
  number, Pulse ID, and a stable fallback source record ID.
- `load_canonical_cti_csv` maps and normalizes records, applies the ATT&CK
  enricher during builds, and stores canonical/enrichment metadata with
  explicit `source_association_only` geography semantics.
- Chunking adds deterministic per-record `chunk_id` metadata.
- `build_vector_store.py` defaults to `data/vector_store_phase1` and refuses
  any pre-existing output directory.
- Regression coverage is in `backend/test_ingestion_foundation.py`.

### Phase 1 validation result: complete

- Interpreter: repository `.venv`, Python 3.12.6. Configured model:
  `sentence-transformers/all-MiniLM-L6-v2`.
- Model was already available in the Hugging Face cache at snapshot
  `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`. It loaded in offline mode and
  returned 384-dimensional embeddings. No network-setting changes or model
  substitution were made. DNS lookup and TCP 443 to `huggingface.co` fail in
  this environment, but the local model cache was complete.
- Built the new index with
  `..\\.venv\\Scripts\\python.exe build_vector_store.py --output data/vector_store_phase1`
  from `backend/`, with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`.
- New index: `IndexFlatIP`, 384 dimensions, 2,820 vectors, 2,820 stored
  documents. FAISS metadata agrees with both counts. The existing
  `backend/data/vector_store` was not targeted.
- Loaded the new index and ran four semantic smoke queries (ransomware,
  phishing credential theft, malware C2 infrastructure, and healthcare
  targeting). Each returned ranked records. These are smoke checks, not a
  measured retrieval benchmark; the healthcare query's top result was a
  government report.
- Integrity audit: all 2,364 source rows are represented; no source-row
  metadata discrepancies; 2,820/2,820 chunk IDs are present and unique; all
  chunks have source, canonical CTI, ATT&CK enrichment, and geography semantics
  metadata. All 2,820 geography labels are `source_association_only`. There
  are 1,305 rows with no country association, retained as unknown/empty rather
  than inferred. No standalone `nan` tokens remain in chunk content. The
  normalized ATT&CK reference count is 27,928.
- Tests: the baseline suite passed (13 tests); the Phase 1/CTI regression suite
  passed after final changes (18 tests). `git diff --check` passed, with only a
  Git line-ending warning for `backend/app/rag/loader.py`.

### Phase 2 implementation and validation (2026-11-14)

Implementation:

- Added `backend/app/rag/document_identity.py` to keep source-record IDs separate from stable chunk IDs, with deterministic legacy fallbacks.
- Semantic retrieval and hybrid fusion deduplicate by chunk ID. Candidate union no longer overwrites chunks that share a Pulse ID.
- Country filtering uses exact canonical comparison and the existing CTI country alias map. Tests cover India vs British Indian Ocean Territory, United States vs United States of America, OR matching, AND matching, and source-association semantics. Other metadata keeps its prior containment behavior.
- Hybrid retrieval keeps weighted fusion as the default and adds selectable weighted Reciprocal Rank Fusion (`fusion_strategy="rrf"`). Fusion ranking determines a bounded cross-encoder pool (20 candidates by default).
- Reranker inputs are capped at 512 tokens by default. Its bounded header retains title, malware, ATT&CK IDs, industry, source-country association, and tags before document evidence. Scores are relevance logits, not probabilities.
- Added `rank-bm25==0.2.2`, a manually checked positive-label dataset at `backend/data/evaluation/phase2_retrieval.json`, and `backend/evaluate_retrieval.py`. The evaluator validates labeled source rows and titles against the Phase 1 reference index.
- Updated `backend/test_vector_store.py` so its persistence round-trip uses an automatically cleaned temporary directory, protecting the original store when pytest collects this legacy script.
- Added `backend/test_phase2_retrieval.py` and `backend/test_reranker_limits.py`.

Evaluation on eight positive-only queries (candidate depth 100, 20 candidates sent to reranking; unlisted records are unjudged, not negatives):

| Stage | Strategy | Recall@5 | MRR | nDCG@5 | Median latency |
|---|---|---:|---:|---:|---:|
| Candidate fusion | Weighted | 1.0000 | 0.6604 | 0.7436 | 17.11 ms candidate generation + fusion |
| Candidate fusion | RRF | 0.8750 | 0.6823 | 0.7202 | 16.89 ms candidate generation + fusion |
| After cross-encoder | Weighted | 1.0000 | 0.7812 | 0.8366 | 865.30 ms end to end |
| After cross-encoder | RRF | 1.0000 | 0.7917 | 0.8452 | 832.27 ms end to end |

Candidate/fusion latency is the median over three repeats per query; reranked latency is the median of one run per query across eight queries. This small, positive-only, manually labeled set is preliminary and not representative of all relevant CTI records; it does not establish a general RRF improvement. Weighted fusion remains the default, with RRF available as an option.

Final validation:

- Focused Phase 2, reranker, and pipeline wiring tests: **19 passed**.
- Full backend suite after final edits: **44 passed in 193.75 seconds**.
- One preceding full-suite attempt failed during collection with Windows error
  1455 (paging file too small) because the legacy pipeline demo loaded a second
  Qwen model at import time. `test_rag_pipeline.py` now has a model-free
  orchestration test and keeps the local-model demo behind its `__main__`
  guard; the final full suite passed without increasing system pagefile size.
- `git diff --check`: passed. Git reports line-ending conversion warnings for
  `backend/app/rag/loader.py` and `backend/test_rag_pipeline.py`, but no
  whitespace errors. New Phase 2 files also passed a trailing-whitespace scan.
- SHA-256 comparisons immediately before/after the final full suite found no
  changes to either vector store. No pre-Phase-2 historical hash baseline was
  recorded, so integrity from the start of Phase 2 cannot be hash-compared.
  Final verified digests:
  - Original `data/vector_store`: `index.faiss`
    `BFF3268D0588E319681428977EBCE0261FCFBAABD384F20A38D8C22849B80E0C`;
    `documents.pkl`
    `956C0B483671116B4A60AA4837C61DDEDA95C15A010F7ADF2AB0570D84B183CD`;
    `store_metadata.json`
    `72CB32D54EBDA54B6162DF15E00CB12127710BB79454133F3425359CA7850751`.
  - Phase 1 `data/vector_store_phase1`: `index.faiss`
    `113F9D3E7F5295D32DBDE866CF3E5B191723938E55F6891541A40A361E428DAB`;
    `documents.pkl`
    `33C3F7F7FEE1134B872CB12F735AEEB472171A6452B19D72A0D1B1EFCD31F167`;
    `store_metadata.json`
    `B24010726C6DC2E49D300E0D996909AB97B87A0FBCB31A357834F34B4071B23C`.

Known limitations: evaluation labels are eight positive examples, not an
exhaustive judgment set. Candidate retrieval scores are compared before
reranking; post-rerank metrics come from a single run per query. End-to-end
latency is environment-specific. No API or frontend integration was started.

### Phase 3 implementation and validation (2026-11-15) — complete

Implementation:

- Added `CTIGeographicEvidence`, `GeographicEvidenceRole`, and
  `GeographicEvidenceStatus` to the canonical schema. Evidence records carry
  normalized country/region, role, supporting sentence and location offsets,
  source record ID, deterministic method, confidence, status, provenance, and
  explicit uncertainty. The existing `CTIGeography.countries` field remains
  source-associated metadata and is not converted to incident/origin claims.
- Added `app/geo/geographic_extractor.py`. It extracts recognized country and
  region mentions from the raw source description, applies the existing
  geographic resolver plus reviewed aliases, and classifies explicit incident,
  target, victim, infrastructure, or reported actor-origin cues. Unsupported
  role assignment remains `general_mention`/`ambiguous`; negated locations are
  marked `negated`. Coordinated country lists inherit a role only when the
  connecting text is just punctuation/conjunctions. Actor origin is always
  described as source attribution, never independently verified. IP addresses
  are not used to infer origin.
- Canonical ingestion now stores the exact source description in the canonical
  record, with its original formatted document text, source-associated country
  metadata, ATT&CK enrichment, and stable IDs preserved. Extracted geographic
  evidence is in its own field. Existing FAISS stores were not rebuilt.
- Added `app/geo/geo_analysis.py` for supported incident/target/victim evidence
  filtering and country/region aggregation. It counts distinct source-record
  IDs (so sibling chunks/repeated Pulse rows do not inflate counts), keeps
  source-association counts separate, returns evidence and explicit threat-tag
  counts, and reports records with no evidence separately from records with
  only ambiguous/negated evidence. No risk scores are generated.
- Expanded the resolver’s reviewed country/region coverage for locations in the
  current OTX descriptions, including Mexico and the multi-country examples.
  Aliases are exact boundary matches; `US` requires uppercase or dotted form to
  avoid treating the pronoun `us` as the country. British Indian Ocean
  Territory does not match India.
- The old `test_automatic_metadata_retrieval.py` was an executable demo with
  top-level FAISS/model/index work during pytest collection. Its demo is now
  behind a `__main__` guard, preserving direct execution while keeping test
  collection inert and preventing accidental access to the original index.

Geographic evaluation:

- `backend/data/evaluation/phase3_geographic.json` contains 11 manually
  reviewed OTX source records and 20 labeled location mentions: 4 target, 1
  incident, 4 victim, 4 claimed actor origin, 1 infrastructure, and 6 general
  ambiguous mentions. One record has no location evidence. It covers a
  multiple-country report, and source-associated country metadata is not used
  as gold evidence. No genuine negated-location example was found in the
  reviewed OTX descriptions; a clearly synthetic negation fixture verifies
  conservative behavior and is excluded from metrics.
- On this small, deliberately feature-covering set: mention/role/status
  precision **1.00** (20 TP, 0 FP), recall **1.00** (20 TP, 0 FN), and role
  classification accuracy **1.00** (20/20). These are sample-fit measurements,
  not a broad accuracy claim; aliases/rules and labels share the same source
  distribution and the evaluation is not random or exhaustive.
- Full OTX ingestion audit: 2,364 rows; 700 extracted mentions (198 supported,
  502 ambiguous, 0 negated); no missing canonical descriptions, missing source
  IDs, invalid offsets, or evidence/source-ID mismatches. Twenty-five Pulse IDs
  repeat across source rows; analysis deduplicates those by source-record ID.

Validation:

- Focused Phase 3 geographic, resolver, region, canonical schema, and ingestion
  tests: **11 passed**.
- Automated backend regression suite (all files containing actual pytest test
  functions, launched from `backend/` for data-relative paths): **48 passed**.
  The repository also contains legacy executable `test_*.py` demos with no
  pytest test functions; they are not part of this automated count. A broad
  `pytest backend` collection was not usable: those top-level demos perform
  model/index work at import, and the Windows run hit a native FAISS exception
  before pytest could report results. The retrieval demo was guarded to avoid
  import-time work. Safe lightweight geographic resolver, region,
  metadata-filter, and query-parser demos each completed successfully.
- Focused Phase 3 geographic/resolver/region/schema/ingestion suite: **11
  passed**. Final Phase 3 unit rerun: **5 passed**.
- `git diff --check`: passed; Git emitted existing LF-to-CRLF conversion
  warnings for `backend/app/rag/loader.py` and `backend/test_rag_pipeline.py`,
  with no whitespace errors.
- Both vector stores were hashed before and after Phase 3 validation. Their
  file digests match the Phase 2 verified values recorded above; neither store
  was rebuilt or modified. No new index was created, and weighted retrieval
  remains the default.

Limitations: extraction is deterministic and vocabulary/rule-based. It does
not cover every country/demonym, nuanced clause scope, implicit geographies,
or non-English reports. Geographic roles are source claims, not independently
corroborated facts. Region mappings are coarse and some large/transcontinental
states have an approximate broad-region assignment. Evaluation uses only 11
records from one source.

### Phase 4 implementation and validation (2026-11-15) — complete

#### Test discovery stabilization

- Added `backend/conftest.py` with a reviewed ignore list for demo-only
  `test_*.py` scripts that have no pytest test functions. The demos are
  preserved and remain explicitly runnable with `python test_name.py` from
  `backend/`; collection no longer executes their model/retrieval/index code.
- FAISS is imported once at conftest startup, without opening an index. This
  import order avoids a reproducible Windows native DLL initialization error
  seen when FAISS was first imported during test-module collection after other
  numerical runtimes. Reliable command from `backend/`:
  `..\\.venv\\Scripts\\python.exe -m pytest -q`.
- Baseline before Phase 4 implementation: **48 passed**.

#### Threat correlation

- Added `backend/app/threat_analysis/correlation.py` and centralized
  orchestration in `analysis_engine.py`. The correlator accepts canonical
  records, JSON canonical metadata, or LangChain documents with canonical
  metadata. `ThreatAnalysisEngine.analyze` returns independent correlation and
  contextual-priority outputs; it never folds one score into the other.
- Exact normalized IoCs (when structured), source-reported malware/actor names
  and aliases, optional exact campaign values in raw metadata, and exact CVEs
  are anchors. CVEs are read from canonical vulnerability values and exact
  `CVE-YYYY-NNNN...` strings in the description, with source-record evidence
  snippets. Names/aliases use exact normalized equality, not fuzzy or
  substring matching. The source model has no campaign columns, so campaign
  matching is available only when a caller provides a campaign field.
- Shared ATT&CK IDs, supported geographic overlap, and publication-time
  proximity are supporting evidence only. A relationship is never emitted
  from ATT&CK, geography, or time alone. Source country-association metadata
  is ignored. Pairwise edges are not transitively expanded; duplicate source
  IDs/pairs are collapsed. The edge includes source IDs, matched entities,
  evidence/provenance, factor contributions, relationship types, explanation,
  and an uncalibrated 0–1 evidence-strength heuristic (not a probability).
- Default configurable weights and rationale: exact structured IoC **0.85**,
  exact reported malware/actor/campaign **0.70**, exact CVE **0.25**, shared
  ATT&CK **0.10**, geographic overlap **0.08**, and time proximity within a
  configurable 90-day reporting window **0.05**. Specific identifiers carry
  the larger weight; ATT&CK/geography/time are deliberately low and cannot
  independently create a relationship. The combined heuristic is
  `1 - product(1 - active_factor_weight)`; each factor contributes at most once
  regardless of the number of matching values. The 0.20 minimum threshold is
  configurable. Scores are not empirically calibrated.

#### Contextual prioritization

- Added `backend/app/threat_analysis/priority.py`. It produces a separate
  0–100 contextual review-priority score and factor evidence. It is not a
  probability, intrinsic severity grade, or forecast.
- Actual OTX fields support timestamps, target industries, ATT&CK references,
  descriptions, and Phase 3 geographic evidence. The CSV has 2,365 rows and
  one blank description; `Indicators_Count` is zero for every row, there are
  no campaign/severity/CVSS/exploitation-status/source-reliability columns,
  and `Author` is the same source label for all rows. Actor names are not
  populated into the canonical `threat_actors` field by this CSV mapper.
  Consequently, no severity, source reliability, CVSS, raw IOC-presence,
  ATT&CK severity, or retrieval similarity factor is scored. Structured IoCs
  and canonical actors still work if supplied to the analysis engine.
- Scored factors: explicitly worded source exploitation claim **0.40**;
  analyst-supplied industry match **0.20**; analyst-supplied geography match
  against supported incident/target/victim evidence **0.20**; report recency
  **0.20**, linearly decayed across a configurable 365-day horizon. The
  exploitation weight is twice each contextual/freshness dimension because it
  is direct reported activity; the other three are equal-weight context
  signals. These judgment-based weights are configurable and not fit to
  outcomes.
- Context match is relevance to the analyst's selected context, not threat
  severity. Geographic source associations and claimed actor origins do not
  count. Missing factors are excluded from the weighted mean, listed, and
  reflected in a coverage value; missingness is never entered as zero. If no
  configured factor has data, the score is `null`. An explicit source statement
  that exploitation was not observed is retained as a source claim with value
  zero and an explanation that it is not proof of safety. Individual factor
  evidence is returned. Phase 3 extraction confidence is not treated as a
  calibrated risk probability.
- To limit double counting, malware, actor, ATT&CK, TLP, and vulnerability
  presence are not separately added to priority. The scoring dimensions are
  reported exploitation, user-selected relevance, and recency; severity-like
  fields are unavailable. Correlation confidence is not reused for priority.

#### Evaluation and tests

- `backend/data/evaluation/phase4_correlation.json` contains three manually
  checked pairs from actual OTX reports: two expected links grounded in shared
  reported malware/CVEs and one negative pair with generic ATT&CK overlap only.
  Results: **TP=2, FP=0, FN=0, TN=1**, precision **1.00**, recall **1.00**.
  This three-pair, feature-selected test is only a sanity check; zero false
  positives on one negative pair does not establish a production false
  positive rate. A positive link means related CTI evidence, not the same
  campaign.
- `backend/data/evaluation/phase4_priority_examples.json` records three
  source-grounded examples for active exploitation, industry matches, missing
  geography, and claimed actor-origin exclusion. Tests verify factor states
  and explanations; these are not independent expert adjudication or
  predictive labels. No predictive accuracy is claimed.
- Phase 4 files: `backend/conftest.py`,
  `backend/app/threat_analysis/correlation.py`,
  `backend/app/threat_analysis/priority.py`,
  `backend/app/threat_analysis/analysis_engine.py`,
  `backend/test_phase4_analysis.py`, and the two Phase 4 JSON evaluation files.
  Project status and methodology are documented in this handoff and `README.md`.
- `backend/test_phase4_analysis.py`: **15 passed** (includes the actual OTX
  pair evaluation, three actual priority examples, and synthetic unit cases
  for hashes/domains/IPs, names/aliases, CVEs, campaign metadata, techniques,
  geo/time, duplicate pairs, missing/conflicting factors, recency, and
  orchestrator separation).
- Baseline automated tests: **48 passed**. Final stabilized backend suite
  including Phases 1–4: **63 passed in 86.72 seconds**. Script-only legacy demos
  are excluded by conftest but remain callable directly.
- `git diff --check`: passed with no whitespace errors (Git only reports
  line-ending conversion notices for existing files).
- Both vector stores were hashed before and after Phase 4 tests; hashes match
  the Phase 3/Phase 2 digests already recorded above. No build was run and no
  index path was opened by the correlation or priority modules.

Limitations: OTX structured indicators are absent in this snapshot; the
correlator does not scrape raw description text for IPs/domains because those
could be infrastructure rather than IOCs. Actor names and campaigns are not
populated in current source metadata, so those paths are supported/tested with
canonical records but not measured on the source pair set. CVE overlap is a
contextual relationship, not proof of common actors. Correlation and priority
weights are transparent but judgment-based and uncalibrated. The evaluation
set is small, selected, and not independently adjudicated. Priority depends
on analyst context and is only for review ordering; no future incident
prediction is made.

### Phase 5 — agentic RAG architecture (complete)

- Added `backend/app/agents/{models.py,planner.py,specialists.py,orchestrator.py}`.
  Query planning reuses the Phase 2 parser/filter builder. It always selects
  retrieval and evidence response, and conditionally selects geographic,
  correlation, and contextual-priority analysis based on deterministic query
  intent rules. Geographic queries do not filter on source-associated country
  metadata; the geographic specialist uses Phase 3 supported evidence only.
- Retrieval uses the existing Phase 2 hybrid retriever with weighted fusion
  retained as the default and RRF available on the retriever. A single retriever
  and generator instance are shared; no embedding/reranker/Qwen model is loaded
  separately by each agent. Retrieval evidence retains both stable chunk IDs
  and source-record IDs, provenance, and raw relevance score with explicit
  score semantics.
- Geographic analysis reuses supported location filtering and distinct-source
  aggregation. Correlation and contextual priority reuse the Phase 4 analysis
  engine services and keep their evidence-strength/priority values separate
  from retrieval relevance. The response prompt includes a source registry and
  structured specialist outputs; unsupported generated answers without valid
  source labels fall back to a deterministic source-linked evidence summary.
- The trace records selected and skipped agents, reasons, statuses, duration,
  record IDs, missing information, warnings, and errors. Independent
  specialists run concurrently with a configurable timeout; response
  generation has its own configurable timeout. Failures are isolated and
  represented as partial execution. A timed-out Python worker cannot be
  forcibly stopped and may finish in the background. Empty retrieval returns
  an explicit insufficient-evidence response without generation.
- The direct pipeline retains `query`, `answer`, `retrieved_documents`, and
  `prompt`; it adds structured `plan`, `agent_results`, `execution_trace`, and
  `warnings`. Phase 6 exposes typed, sanitized diagnostic fields through the
  FastAPI response while preserving the original `query`, `answer`, `sources`
  fields.
- Phase 5 files: `backend/app/agents/__init__.py`, `models.py`, `planner.py`,
  `specialists.py`, `orchestrator.py`; `backend/app/rag/pipeline.py`,
  `backend/app/rag/prompt.py`; and `backend/test_phase5_orchestration.py`.
  The prompt now labels scores as retrieval relevance, not probability or
  factual confidence.
- Tests: Phase 5 plus existing pipeline wiring **11 passed in 10.30 seconds**;
  the final full backend suite **73 passed in 60.99 seconds**. Coverage includes conditional planning,
  sibling chunks/source identity, source-associated country separation,
  empty evidence, citation fallback, invalid plans, retrieval failure,
  specialist and generator timeout/failure, and legacy pipeline construction. Model loading
  is not exercised by the model-free orchestration tests.
- `git diff --check`: passed after the Phase 5 code and documentation edits.
  Post-test hashes matched the recorded Phase 4 hashes for all three files in
  both `backend/data/vector_store` and `backend/data/vector_store_phase1`; the
  exact matching digests are listed in the Phase 2/4 integrity records above.
  Neither index was rebuilt or opened by the new tests.

Limitations: intent detection is deterministic and phrase-based, so indirect or
multilingual requests can miss a specialist. Cross-encoder relevance logits
are not probabilities. Citation fallback provides source-linked excerpts but
does not validate every claim in arbitrary model output when the model emits
one valid label. A worker that times out cannot be forcibly stopped.

### Phase 6 — API, dashboard, and operational integration (implementation complete; model runtime gate open)

- Updated `backend/app/main.py` with lazy pipeline initialization, one-time
  initialization locking, safe structured 500/422 responses, server-only
  exception logging, request IDs, CORS allow-list configuration, `/health`
  liveness, and `/ready` readiness. Failed model initialization is cached for
  that process so repeated queries do not repeatedly allocate model memory;
  restart the server to retry after resolving the local constraint.
- Added `backend/app/api/schemas.py` with trimmed 1–4,000-character query
  validation and typed query/source/health/readiness response models. `/query`
  preserves `query`, `answer`, and `sources`, and adds geographic findings,
  threat correlations, contextual priorities, execution plan/results/trace,
  warnings, missing evidence, and partial status. Source records retain stable
  source-record and chunk IDs, relevance score semantics, excerpt, provenance,
  ATT&CK enrichment, and evidence. API sanitation removes private prompts,
  local paths, and internal exception details before returning diagnostics.
- Replaced the all-empty frontend stubs with a dependency-free HTML/CSS/JS
  dashboard: `frontend/index.html`, `src/styles.css`, `src/app.js`,
  `src/services/api.js`, and `src/services/viewModel.js`. `frontend/serve.py`
  injects a runtime API URL from `GEORAG_API_URL`; no backend URL is compiled
  into the client. The dashboard presents query/loading/error states, answer,
  evidence-backed geography, correlations, contextual priority, ATT&CK,
  source provenance, and expandable execution trace. It uses safe text nodes.
  Because OTX records have no verified incident coordinates, the UI shows an
  evidence table and an explicit no-coordinate notice instead of a map. It
  separates source-country associations from supported roles.
- Setup is documented in `README.md` and `frontend/README.md`. Backend
  configuration includes `GEORAG_VECTOR_STORE_PATH`,
  `GEORAG_GENERATOR_MODEL`, `GEORAG_TOP_K`, `GEORAG_MAX_NEW_TOKENS`,
  `GEORAG_AGENT_TIMEOUT_SECONDS`, and `GEORAG_CORS_ORIGINS`; frontend runtime
  configuration uses `GEORAG_API_URL` and `GEORAG_FRONTEND_PORT`.
- Tests: final full backend suite **80 passed in 65.74 seconds**. Phase 6
  backend checks include request validation, response schema/OpenAPI,
  back-compat fields, nested findings and trace, safe errors, readiness,
  CORS configuration, and one-time lazy construction. Full frontend suite:
  **6 passed** with Node syntax checks and Python frontend server compilation
  also passing. The installed Starlette 1.6/httpx 0.28 `TestClient` blocked on
  requests even against a minimal FastAPI app. Therefore route contract tests
  call route handlers directly, not through that client. A real Uvicorn
  process started; local `GET /health` returned `healthy`, and `GET /ready`
  returned 503 before model initialization. The browser loaded the local
  frontend and its ready/empty state was visually inspected. No browser `/query`
  was sent because that would repeat the already-confirmed Qwen load failure.
- Actual local-model test is mandatory and **did not pass**. On 2026-11-16
  local time, `run_phase6_model_smoke.py` loaded the cached
  `sentence-transformers/all-MiniLM-L6-v2`, FAISS `data/vector_store` (100
  vectors, 384 dimensions), cross-encoder, and Qwen tokenizer. Loading Qwen
  weights then failed with Windows `OSError 1455`: “The paging file is too
  small for this operation to complete.” At measurement, available system
  memory was 1,980 MiB and Qwen's cached model files totaled 2,955.4 MiB.
  Consequently, **zero of the five required queries completed** and there are
  no query latency, answer, source relevance, or specialist runtime results.
  Exact attempt details and queries are in
  `docs/phase6_local_model_smoke.json`. The correct models were not substituted;
  network/security settings and Windows paging configuration were not changed.
- Resource review found that model instances are created once and API
  health/import do not load models. The API sets `OPENBLAS_NUM_THREADS=1` and
  `OMP_NUM_THREADS=1` only if the user has not set values, avoiding large
  per-core BLAS pools under memory pressure. This did not remove the Windows
  memory commit limitation. No query latency measurement is available.
- Integrity checks after the Phase 6 backend suite matched recorded baselines
  for all files in `backend/data/vector_store` and
  `backend/data/vector_store_phase1`. No index build or write was run. Existing
  Git-reported vector-store modifications predate Phase 6; the baseline hashes
  remained unchanged. `git diff --check` passed; Git printed only its usual
  line-ending conversion notices. New Phase 6 files also passed a trailing
  whitespace scan and Python/JavaScript syntax checks.

**Phase 6 completion gate:** Qwen must generate successful answers within the
configured timeout and browser-to-backend query integration must be validated.
For a repeat smoke test from `backend/`:

```powershell
..\.venv\Scripts\python.exe run_phase6_model_smoke.py --vector-store data/vector_store_phase1 --top-k 5 --tokens 64
```

Keep the same cached embedding model, reranker, and Qwen model; do not rebuild
either vector store. Phase 7 is not started.

## Portable MITRE ATT&CK dataset bootstrap (2026-11-22)

### Implementation

- Added `backend/download_mitre_attack.py`, using only the standard library to
  download MITRE/CTI Enterprise ATT&CK release **ATT&CK-v20.1** from
  `https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v20.1/enterprise-attack/enterprise-attack.json`.
  MITRE's [release page](https://github.com/mitre/cti/releases/tag/ATT%26CK-v20.1)
  and [STIX 2.0 repository documentation](https://github.com/mitre/cti) confirm
  the pin/source. This STIX 2.0 source matches the project's existing
  `mitreattack.stix20.MitreAttackData`; the separate `attack-stix-data`
  repository publishes STIX 2.1 collections.
- It validates JSON, STIX bundle structure and ID, STIX 2.0/2.1 spec version,
  and at least 500 Enterprise attack-pattern objects before destination writes.
  The count threshold rejects small JSON-valid partial files, though it cannot
  prove all objects from the pinned release are present. It stages dataset and
  manifest in the same directory, then atomically replaces each destination.
  A valid existing dataset is reused unless `--force` is explicit. Invalid
  existing data, malformed downloads, and network failures do not replace the
  dataset.
- Successful download manifest:
  `backend/data/mitre/enterprise-attack.json.manifest.json`; fields include
  repository/URL, release/version/tag, UTC download timestamp, SHA-256, STIX
  version, object count, and Enterprise attack-pattern count. Existing
  `.gitignore` rule `backend/data/mitre/` excludes both data and manifest.
  No live dataset download was done during this work or its tests.
- `load_attack()` and `load_attack_history()` remain file readers, preserving
  active technique enrichment and revoked/deprecated historical enrichment.
  `backend/build_vector_store.py` calls `load_attack()` before reading and
  enriching CTI rows. Required order: install dependencies -> bootstrap MITRE
  file -> build a new Phase 1 index -> start FastAPI -> start the frontend.
- Runtime app, API, chat, retriever, and smoke-test defaults use
  `data/vector_store_phase1`; `GEORAG_VECTOR_STORE_PATH` and smoke
  `--vector-store` remain explicit overrides. The retrieval evaluation and
  builder already defaulted to Phase 1. Existing demo/test hard-coded paths
  were not changed wholesale.

### Validation and current limitation

- The pinned `ATT&CK-v20.1` release and versioned raw asset path were verified
  against MITRE's official GitHub release/repository pages. The corresponding
  dataset was not fetched. The actual existing local bundle is a valid STIX 2.0
  Enterprise dataset (26,086 objects; 858 Enterprise attack-pattern objects;
  53,835,637 bytes). It has no sidecar manifest, so its original release and
  download timestamp are unknown and are not inferred. Running the bootstrap
  without `--force` returned `already_present`; it did not download or replace
  it. No test performs a network request or downloads the real dataset.
- Bootstrap tests: **11 passed** (`test_download_mitre_attack.py`, 0.76 s).
  Full backend pytest suite: **91 passed** (148.50 s). Focused MITRE/current
  and historical enrichment plus ingestion group: **22 passed** (157.69 s).
  Coverage includes mocked success and manifest fields, invalid JSON, invalid
  STIX root/spec, incomplete pattern count, network failure, reuse of an
  existing valid dataset without network, forced refresh, and preservation of
  existing data after failed refresh.
- Compile check passed for `backend/app`, bootstrap, builder, chat, smoke test,
  and bootstrap test modules using `python -m compileall -q`. `git diff --check`
  passed; Git emitted only existing line-ending conversion notices.
- SHA-256 checks before and after tests matched for every file in both vector
  stores. The existing local MITRE file also matched its pre-validation hash.
  No index or dataset was modified. The MITRE folder is confirmed ignored by
  `.gitignore`.

| File | SHA-256 after validation (matches pre-validation) |
| --- | --- |
| `backend/data/vector_store/documents.pkl` | `956C0B483671116B4A60AA4837C61DDEDA95C15A010F7ADF2AB0570D84B183CD` |
| `backend/data/vector_store/index.faiss` | `BFF3268D0588E319681428977EBCE0261FCFBAABD384F20A38D8C22849B80E0C` |
| `backend/data/vector_store/store_metadata.json` | `72CB32D54EBDA54B6162DF15E00CB12127710BB79454133F3425359CA7850751` |
| `backend/data/vector_store_phase1/documents.pkl` | `33C3F7F7FEE1134B872CB12F735AEEB472171A6452B19D72A0D1B1EFCD31F167` |
| `backend/data/vector_store_phase1/index.faiss` | `113F9D3E7F5295D32DBDE866CF3E5B191723938E55F6891541A40A361E428DAB` |
| `backend/data/vector_store_phase1/store_metadata.json` | `B24010726C6DC2E49D300E0D996909AB97B87A0FBCB31A357834F34B4071B23C` |
| `backend/data/mitre/enterprise-attack.json` | `DC1639CAA5501D720E280CF1CBD8FBE009884A0C9B3E6E9ED9D0C25166C3D8F4` |
- Follow-up local-model run on 2026-11-16 used `data/vector_store_phase1`
  (2,820 vectors). The embedding model, cross-encoder, and Qwen weights loaded;
  all five retrieval/orchestration requests returned sources. Qwen generation
  exceeded the 120-second agent timeout for all five, so responses were
  evidence fallbacks rather than generated answers. Total query durations were
  122.0–123.7 seconds and evidence-response status was partial. Browser query
  integration is still unverified; Phase 6 is open and Phase 7 has not started.
  See `docs/phase6_local_model_smoke.json`.
