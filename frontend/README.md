# GeoRAG-CTI Workbench

The repository's previous frontend files were empty stubs. This Phase 6 UI is a
dependency-free browser module (HTML, CSS, and JavaScript) so it can be run
without adding a framework or package download.

In PowerShell, start the API from `backend/`:

```powershell
$env:GEORAG_VECTOR_STORE_PATH = "data/vector_store"
..\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

In another PowerShell window, from the repository root:

```powershell
$env:GEORAG_API_URL = "http://127.0.0.1:8000"
python frontend\serve.py
```

Open `http://127.0.0.1:5173`. The API address is provided to the browser from
the runtime `GEORAG_API_URL` environment variable; it is not compiled into the
frontend. To run frontend unit tests:

```powershell
cd frontend
npm test
```

Geographic results are shown as evidence tables. The UI deliberately does not
place markers from country names, source-association metadata, actor-origin
claims, or infrastructure locations because the dataset does not provide
verified coordinates for incident events.
