"# Geo-Aware-RAG-for-Cyber-Threat-Intelligence"

## Development status — 2026-11-22

## New laptop setup: MITRE dataset and Phase 1 index

The Enterprise ATT&CK STIX 2.0 dataset is downloaded locally and ignored by
Git. The bootstrap script pins MITRE/CTI release **ATT&CK-v20.1** and validates
the STIX bundle, Enterprise attack-pattern content, and a minimum object count
before atomically installing it. STIX 2.0 is intentional: the existing
`mitreattack.stix20.MitreAttackData` collector consumes that format. The
separate `attack-stix-data` repository is STIX 2.1 and is not used here. The
script records release, official source URL, UTC download time, object counts,
and SHA-256 in
`backend/data/mitre/enterprise-attack.json.manifest.json`. A valid local
dataset is reused by default; `--force` is required for a refresh.

From a fresh clone in Windows PowerShell, install dependencies and prepare the
local data in this order:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Set-Location backend
..\.venv\Scripts\python.exe download_mitre_attack.py
..\.venv\Scripts\python.exe build_vector_store.py --output data/vector_store_phase1
```

The MITRE download is required **before** building an index: the build script
calls the active ATT&CK collector to enrich technique IDs. The output path is
deliberately required to be new; the builder refuses to overwrite an existing
index. Both the dataset and generated indexes are local files ignored by Git.
To explicitly refresh the MITRE file after review, run
`..\.venv\Scripts\python.exe download_mitre_attack.py --force` from
`backend/`.

Start the backend only after the Phase 1 index exists. The API, interactive
chat, direct retriever/pipeline, and model smoke-test defaults now select
`data/vector_store_phase1`. An explicit `GEORAG_VECTOR_STORE_PATH` value or
smoke-test `--vector-store` argument still overrides the default. To select
the historical 100-vector index intentionally, set the environment variable
to `data/vector_store` yourself.

From `backend/`, in one PowerShell window:

```powershell
$env:GEORAG_VECTOR_STORE_PATH = "data/vector_store_phase1"
$env:GEORAG_GENERATOR_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
$env:GEORAG_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
..\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

Then, from the repository root in a second PowerShell window:

```powershell
$env:GEORAG_API_URL = "http://127.0.0.1:8000"
.\.venv\Scripts\python.exe frontend\serve.py
```

Open `http://127.0.0.1:5173` after both services start. MITRE source:
[official MITRE/CTI ATT&CK-v20.1 release](https://github.com/mitre/cti/releases/tag/ATT%26CK-v20.1).

### Phase 1: data foundation and ingestion — complete

CSV ingestion now drops null-like values instead of emitting `nan`, keeps
source file/row/record provenance, and has a canonical loading path that maps,
normalizes, and can enrich ATT&CK references before indexing. Source `Countries`
remain geographic associations; ingestion does not label them incident or
attacker locations. Split chunks carry stable `chunk_id` values.

Build a new index from `backend/` with:

```powershell
..\.venv\Scripts\python.exe build_vector_store.py --output data/vector_store_phase1
```

The alternate index was built and validated at `backend/data/vector_store_phase1`:
2,820 vectors and documents, 384 dimensions, all 2,364 source rows represented,
and all chunks carrying unique IDs and provenance. The existing
`backend/data/vector_store` was not targeted. The model was loaded from the
local Hugging Face cache in offline mode. The Phase 1/CTI regression suite
passed (18 tests). See `CODEX_HANDOFF.md` for detailed checks.

### Phase 2: retrieval quality and reliability — complete

Semantic retrieval and hybrid fusion now deduplicate by stable chunk IDs;
source-record IDs remain separate. Country filters use exact normalized
matching and known aliases, while non-country metadata retains its earlier
matching behavior. Hybrid retrieval supports weighted fusion (still the
default) and selectable RRF. Cross-encoder inputs are bounded to 512 tokens
with relevant CTI metadata retained.

On the eight-query, positive-only evaluation set, pre-rerank weighted fusion
scored Recall@5 1.000, MRR 0.660, nDCG@5 0.744; RRF scored 0.875, 0.682, 0.720.
After reranking, weighted scored 1.000, 0.781, 0.837; RRF scored 1.000, 0.792,
0.845. Median end-to-end latency was 865 ms weighted and 832 ms RRF in a single
evaluation pass. These preliminary labels are limited and non-exhaustive; they
do not establish general RRF superiority. See `CODEX_HANDOFF.md` for candidate
generation latency, query details, test results, and the proposed Phase 3 work.
The final focused suite passed (19 tests), the full backend suite passed
(44 tests), and pre/post SHA-256 checks confirmed both vector stores were
unchanged during the final full test run.

### Phase 3: evidence-based geographic intelligence — complete

Canonical CTI records now store a separate `geographic_evidence` collection.
Each entry contains a normalized country or region, an explicit role
(incident, target, victim, infrastructure, claimed actor origin, or general
mention), the source sentence and text offsets, source-record ID, extraction
method, confidence/status, provenance, and uncertainty. The original
`geography.countries` remains source-associated metadata. Ingestion preserves
the exact source description, ATT&CK enrichment, existing metadata, and stable
source/chunk identities.

The deterministic rule extractor classifies only contextual location cues.
Ambiguous mentions remain ambiguous; negated mentions are excluded from
supported geography analysis; reported actor origins and infrastructure are
not treated as incident locations. It never infers actor origin from an IP
address. Geographic aggregation filters to supported incident/target/victim
claims, counts distinct source records, returns supporting evidence, reports
explicit threat tags, and keeps source-association counts separate from
evidence-supported counts. Records with no location evidence are reported
separately from records with only ambiguous or negated evidence. No risk
scoring or index rebuild was performed.

The manually reviewed sample has 11 OTX records and 20 location labels across
target (4), incident (1), victim (4), claimed actor origin (4), infrastructure
(1), and ambiguous/general mention (6); one record has no location evidence.
The sample measured mention/role/status precision 1.00, recall 1.00, and role
classification accuracy 1.00 (20/20). This small, selected sample is not
representative and does not establish general geographic extraction accuracy.
No genuine negated-location statement was present in the reviewed OTX sample;
negation is covered separately by a synthetic unit test. The whole-dataset
ingestion audit found 700 mentions in 2,364 rows, with no invalid spans or
source-ID mismatches. See `CODEX_HANDOFF.md` for details and limitations.

Phase 3 validation: 48 automated backend tests passed, covering every backend
file with actual pytest test functions. The repository also has legacy
top-level `test_*.py` demo scripts that run FAISS/model operations during
collection; a broad directory collection hit a Windows native FAISS exception,
so those scripts were not treated as pytest tests. Safe lightweight geographic
resolver, region, metadata filter, and query-parser demos completed. Both
existing vector stores retain their Phase 2 SHA-256 hashes; they were not
modified. Existing weighted retrieval remains the default.

### Phase 4: threat correlation and contextual prioritization — complete

`backend/app/threat_analysis/correlation.py` provides exact normalized
correlation for structured IoCs, reported malware and actor names/aliases,
optional campaign metadata, and exact CVE references. ATT&CK overlap,
supported geographic overlap, and publication-time proximity are low-weight
support only; none creates a relationship by itself. The output includes
matched entities, both source IDs, provenance/evidence, factor contributions,
and an uncalibrated evidence-strength score. A relationship is not proof of a
shared campaign. `analysis_engine.py` orchestrates correlation and
prioritization independently.

`priority.py` returns a configurable 0–100 contextual review-priority score,
not a probability or forecast. Its judgment-based weights are 0.40 for an
explicit exploitation claim, 0.20 for analyst-selected industry relevance,
0.20 for analyst-selected geography supported by incident/target/victim
evidence, and 0.20 for information recency. Missing factors are excluded,
listed, and reflected in coverage; no-data yields an unknown score. Source
country associations and claimed actor origins do not count as target
geography. Severity, CVSS, source reliability, ATT&CK severity, and retrieval
similarity are excluded because current OTX records do not support those
values. See `CODEX_HANDOFF.md` for the weight rationale and limits.

The actual-record correlation sanity sample contains three reviewed pairs:
2 true positives, 0 false positives, 0 false negatives, and 1 true negative
(precision 1.00, recall 1.00). It is too small and selected to estimate
production correlation quality. Three actual records also exercise priority
factor handling; no predictive accuracy is claimed. The source snapshot has
2,365 rows, zero structured indicators, no campaign/severity columns, and no
structured actor values from its current mapper. Actor/campaign and IOC paths
are supported for canonical input and covered by controlled unit tests, but
are not measured on OTX pairs.

Pytest discovery is stabilized by `backend/conftest.py`, which skips legacy
demo-only `test_*.py` files that otherwise perform model/index work at import.
The demos remain explicitly runnable. From `backend/`, run:

```powershell
..\.venv\Scripts\python.exe -m pytest -q
```

Baseline before Phase 4: 48 passed. Final Phase 1–4 suite: **63 passed**,
including 15 Phase 4 tests. Phase 5 final backend suite: **73 passed**, with
11 focused orchestration and pipeline tests. Both existing vector stores
retain their recorded SHA-256 hashes; no index was rebuilt or modified.

### Phase 5: agentic RAG orchestration — complete

The central pipeline now plans each query with the existing parser and runs a
shared weighted hybrid retriever, then conditionally invokes evidence-based
geography, threat correlation, and contextual prioritization. It preserves
source-record and chunk identities, provenance, and distinct score semantics.
Independent specialists and generation run with timeout and failure reporting;
the trace records selected/skipped agents, reasons, statuses, and warnings.
Responses include a source registry, and uncited generation falls back to a
source-linked evidence summary. Existing direct pipeline result keys and the
FastAPI response shape remained compatible at the end of Phase 5; Phase 6
extends that API with the trace and sanitized errors below.

Evaluation remains limited to the small Phase 2 retrieval set and Phase 4
reviewed examples; Phase 5 did not claim new retrieval, correlation, or
prioritization accuracy. Phase 5 did not exercise local-model runtime or
arbitrary generated-claim validation. Phase 6's model initialization failure
is recorded below. See `CODEX_HANDOFF.md` for the full phase history and limits.

### Phase 6: API and dashboard integration — implementation complete; runtime gate open

The FastAPI application now exposes `/health` (liveness), `/ready` (pipeline
readiness), and `/query`. The query response keeps the original `query`,
`answer`, and `sources` fields and adds geographic evidence, threat
correlations, contextual priorities, the selected plan, agent results,
execution trace, warnings, missing evidence, and partial-result status.
Pydantic models validate requests and responses; request text is trimmed and
limited to 4,000 characters. Internal exceptions, stack details, prompt text,
and local paths are removed from client responses. API initialization is lazy
and cached so health checks do not load Torch or models. CORS origins and model,
retrieval, token, and timeout values are configurable with `GEORAG_*` variables.

The previously empty frontend files now form a dependency-free responsive
browser dashboard using HTML, CSS, and JavaScript. It includes query/loading
and error states; the generated response; supported geography and separate
source-country associations; correlations; contextual-priority factors,
coverage and missing data; ATT&CK identifiers/names when present; provenance
and source excerpts; and an expandable agent trace. The app reads its API URL
from runtime `GEORAG_API_URL`. It uses an evidence table instead of a map:
country mentions do not supply verified event coordinates. Text is rendered
through `textContent` to avoid interpreting CTI report text as markup.

#### Local startup

From `backend/`:

```powershell
$env:GEORAG_VECTOR_STORE_PATH = "data/vector_store_phase1"
$env:GEORAG_GENERATOR_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
$env:GEORAG_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
..\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

From the repository root, in another PowerShell window:

```powershell
$env:GEORAG_API_URL = "http://127.0.0.1:8000"
.\.venv\Scripts\python.exe frontend\serve.py
```

Open `http://127.0.0.1:5173`. `GET /health` is a liveness check and does not
load models. `GET /ready` returns 503 until pipeline initialization succeeds.
The first `/query` loads one shared embedding model, reranker and generator.
After a pipeline initialization failure, restart the API process to retry; it
does not repeatedly attempt an expensive model load for each request.

#### Phase 6 verification

- Backend: full suite **80 passed in 65.74 seconds**. Phase 6 API contract
  coverage includes request limits/blank queries, health/readiness state,
  lazy one-time pipeline initialization, legacy fields, response schema,
  nested findings/trace, sanitized failures, and CORS configuration. The
  existing Phase 1–5 tests also passed. The installed Starlette/httpx
  `TestClient` blocks even on a minimal app in this environment, so API tests
  exercise route handlers and OpenAPI contracts directly instead of asserting
  HTTP status through that broken client. The running Uvicorn `/health` GET
  returned `healthy`; `/ready` correctly returned 503 before model
  initialization. A browser screenshot verified the dashboard ready/empty
  state. A complete browser query against the local model was not possible.
- Frontend: `npm test` **6 passed**; Node syntax checks and `frontend/serve.py`
  Python compilation passed. Tests cover configured API URL, request/response
  handling, network/API errors, evidence rendering view models, role/source
  separation, correlation, priority, trace, partial states, and empty/legacy
  results.
- Actual local-model gate: the configured MiniLM embedding model, cross-encoder
  and Qwen weights loaded with 4,484 MiB available RAM using
  `data/vector_store_phase1` (2,820 vectors). All five retrieval/orchestration
  queries ran, but Qwen generation exceeded its 120-second agent timeout on
  every query. The responses were evidence fallbacks, not generated Qwen
  answers; all evidence-response agents were partial, with per-query wall times
  of 122.0–123.7 seconds. The initial OSError 1455 from 1,980 MiB available RAM
  remains historical context. See `docs/phase6_local_model_smoke.json` for
  sources, traces, warnings, and memory.
- Memory/resource check: memory and model instances are shared once per
  pipeline. `OPENBLAS_NUM_THREADS` and `OMP_NUM_THREADS` default to 1 only when
  the user has not already configured them, to limit per-worker memory under
  constrained local execution. Memory was sufficient to load Qwen on the later
  attempt; CPU generation latency remains the runtime limitation. No
  network/security setting or page-file configuration was changed.
- The original and Phase 1 vector-store SHA-256 values matched the previously
  recorded Phase 2/4 baselines after tests. No index build/write was run. The
  existing checkout already has Git-reported changes to original-store files;
  integrity was confirmed by hashes rather than a clean working tree.

Phase 6 remains **open** until Qwen generates successful answers within the
configured timeout and browser-to-backend query integration is validated. To
repeat the actual-model smoke test from `backend/`:

```powershell
..\.venv\Scripts\python.exe run_phase6_model_smoke.py --vector-store data/vector_store_phase1 --top-k 5 --tokens 64
```

The correct cached models must be used; do not substitute or rebuild an index.
After real inference succeeds, record query timings, sources, agent statuses,
answers, warnings and memory use in the report. Phase 7 remains unstarted.
