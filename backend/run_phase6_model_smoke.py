"""Run the required five-query check against existing local models/index.

Run from ``backend/``. The script is offline-only and writes its JSON report
under ``docs/``; it never builds or modifies a vector store.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from app.rag.pipeline import CTIRAGPipeline


QUERIES = [
    ("general", "Summarize ransomware and malware activity in the CTI reports."),
    ("country", "What threat reports are associated with India? Distinguish source association from supported victim or target locations."),
    ("region", "What cybersecurity threats are reported in Southeast Asia?"),
    ("correlation", "Which reports show evidence of shared malware or campaign activity involving LockBit?"),
    ("contextual_priority", "Which retrieved reports should be prioritized for review in the healthcare industry, and why?"),
]


def memory_snapshot() -> dict[str, int] | None:
    """Return Windows system/process memory in MiB when available."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    memory = MemoryStatusEx()
    memory.dwLength = ctypes.sizeof(MemoryStatusEx)
    system = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory))
    output = {"system_available_mib": round(memory.ullAvailPhys / 1024**2)} if system else {}

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(ProcessMemoryCounters)
    ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD,
    )
    ctypes.windll.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    try:
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            output["process_working_set_mib"] = round(counters.WorkingSetSize / 1024**2)
            output["process_peak_working_set_mib"] = round(counters.PeakWorkingSetSize / 1024**2)
    except OSError:
        pass
    return output or None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vector-store", default=os.getenv("GEORAG_VECTOR_STORE_PATH", "data/vector_store_phase1"))
    parser.add_argument("--model", default=os.getenv("GEORAG_GENERATOR_MODEL", "Qwen/Qwen2.5-1.5B-Instruct"))
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--tokens", type=int, default=64)
    parser.add_argument("--output", default="../docs/phase6_local_model_smoke.json")
    args = parser.parse_args()

    started = time.perf_counter()
    before_memory = memory_snapshot()
    try:
        pipeline = CTIRAGPipeline(vector_store_path=args.vector_store, model_name=args.model,
                                  top_k=args.top_k, max_new_tokens=args.tokens)
    except Exception as exc:
        report = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "model": args.model,
            "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
            "reranker_model": "cross-encoder/ms-marco-MiniLM-L-6-v2",
            "vector_store": args.vector_store,
            "offline_only": True,
            "initialization_duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "memory_before_mib": before_memory,
            "memory_after_mib": memory_snapshot(),
            "initialization_status": "failed",
            "initialization_error_type": type(exc).__name__,
            "initialization_error": str(exc),
            "queries": [{"category": category, "query": query, "status": "not_run",
                         "reason": "Pipeline initialization failed before query execution."}
                        for category, query in QUERIES],
        }
        output_path = Path(args.output).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"output": str(output_path), "initialization_status": "failed",
                          "error_type": type(exc).__name__, "error": str(exc),
                          "memory_before_mib": before_memory, "memory_after_mib": report["memory_after_mib"],
                          "queries_not_run": len(QUERIES)}, indent=2))
        return 1
    initialization_ms = (time.perf_counter() - started) * 1000
    rows = []
    for category, query in QUERIES:
        query_started = time.perf_counter()
        try:
            result = pipeline.query(query, max_new_tokens=args.tokens)
            agent_results = result.get("agent_results", {})
            rows.append({
                "category": category, "query": query, "status": "completed",
                "query_duration_ms": round((time.perf_counter() - query_started) * 1000, 1),
                "answer": result.get("answer", ""),
                "sources": [{"title": doc.metadata.get("title"), "source_record_id": doc.metadata.get("source_record_id"),
                             "chunk_id": doc.metadata.get("chunk_id"), "relevance_score": float(score)}
                            for doc, score in result.get("retrieved_documents", [])],
                "agent_statuses": {name: data.get("status") for name, data in agent_results.items()},
                "execution_trace": result.get("execution_trace", {}),
                "warnings": result.get("warnings", []),
            })
        except Exception as exc:
            rows.append({"category": category, "query": query, "status": "failed",
                         "query_duration_ms": round((time.perf_counter() - query_started) * 1000, 1),
                         "error_type": type(exc).__name__, "error": str(exc)})
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": args.model,
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
        "reranker_model": "cross-encoder/ms-marco-MiniLM-L-6-v2",
        "vector_store": args.vector_store,
        "offline_only": True,
        "initialization_status": "completed",
        "initialization_duration_ms": round(initialization_ms, 1),
        "memory_before_mib": before_memory,
        "memory_after_mib": memory_snapshot(),
        "queries": rows,
    }
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"output": str(output_path), "initialization_duration_ms": report["initialization_duration_ms"],
                      "memory_before_mib": report["memory_before_mib"], "memory_after_mib": report["memory_after_mib"],
                      "queries": [{"category": row["category"], "status": row["status"],
                                   "duration_ms": row["query_duration_ms"], "source_count": len(row.get("sources", [])),
                                   "agent_statuses": row.get("agent_statuses", {}), "warnings": row.get("warnings", []),
                                   "error_type": row.get("error_type")} for row in rows]}, indent=2))
    return 0 if all(row["status"] == "completed" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
