"""Conditional orchestration with explicit trace and partial-failure handling."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, wait
from time import perf_counter
from typing import Any

from app.agents.models import AgentExecution, AgentExecutionPlan, AgentInput, AgentResult, AgentStatus, AgentTraceEntry, ExecutionTrace


class CTIAgentOrchestrator:
    AGENT_NAMES = {"query_planning", "retrieval", "geographic", "correlation", "contextual_risk", "evidence_response"}
    SPECIALISTS = ("geographic", "correlation", "contextual_risk")

    def __init__(self, planner: Any, retrieval_agent: Any, geo_agent: Any, correlation_agent: Any,
                 risk_agent: Any, prompt_builder: Any, generator: Any, *, specialist_timeout: float = 20.0,
                 generation_timeout: float = 120.0):
        self.planner, self.retrieval_agent = planner, retrieval_agent
        self.geo_agent, self.correlation_agent, self.risk_agent = geo_agent, correlation_agent, risk_agent
        self.prompt_builder, self.generator = prompt_builder, generator
        self.specialist_timeout = specialist_timeout
        self.generation_timeout = generation_timeout

    def validate_plan(self, plan: AgentExecutionPlan) -> None:
        names = plan.selected_agents
        if len(names) != len(set(names)) or any(name not in self.AGENT_NAMES for name in names):
            raise ValueError("Execution plan contains duplicate or unknown agent names.")
        if not {"query_planning", "retrieval", "evidence_response"}.issubset(names):
            raise ValueError("Execution plan must include planning, retrieval, and evidence response.")

    def _response(self, query: str, docs: list[Any], results: dict[str, AgentResult], max_new_tokens: int | None):
        prompt = self.prompt_builder.build_prompt(query=query, documents=docs)
        refs = results.get("retrieval", AgentResult(agent_name="retrieval", status=AgentStatus.PARTIAL)).evidence_references
        registry = "\n\nSOURCE REGISTRY (cite these labels for factual claims):\n" + "\n".join(
            f"[S{i}] source_record_id={ref.source_record_id}; title={ref.title or 'Unknown'}; excerpt={ref.excerpt[:400]}"
            for i, ref in enumerate(refs, 1))
        analysis = {name: result.output_data for name, result in results.items() if name in self.SPECIALISTS and result.status != AgentStatus.FAILED}
        prompt += registry + "\n\nSTRUCTURED ANALYSIS (evidence-bound; source countries are associations only; priority is not prediction):\n" + str(analysis)
        if not docs:
            return "The available retrieved evidence is insufficient to answer this query.", prompt, AgentStatus.PARTIAL, ["No retrieved evidence; generation skipped."]
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(self.generator.generate, prompt=prompt, max_new_tokens=max_new_tokens)
            answer = future.result(timeout=self.generation_timeout)
            executor.shutdown(wait=False)
            valid = {f"[S{i}]" for i in range(1, len(refs) + 1)}
            citations = set(re.findall(r"\[S\d+\]", str(answer)))
            if refs and not citations.intersection(valid):
                # Deterministic grounded fallback; do not present uncited generation as verified.
                evidence = "; ".join(f"[S{i}] {ref.title or ref.source_record_id}: {ref.excerpt[:220]}" for i, ref in enumerate(refs[:3], 1))
                answer = f"Retrieved evidence relevant to your query: {evidence}"
                return answer, prompt, AgentStatus.PARTIAL, ["Generated response contained no valid source citation; returned a source-linked evidence summary."]
            return str(answer), prompt, AgentStatus.SUCCESS, []
        except FutureTimeoutError:
            executor.shutdown(wait=False, cancel_futures=True)
            evidence = "; ".join(f"[S{i}] {ref.title or ref.source_record_id}: {ref.excerpt[:220]}" for i, ref in enumerate(refs[:3], 1))
            return f"Answer generation timed out. Retrieved evidence: {evidence}", prompt, AgentStatus.PARTIAL, ["Generator exceeded the configured timeout; its worker may finish in the background."]
        except Exception as exc:
            executor.shutdown(wait=False, cancel_futures=True)
            evidence = "; ".join(f"[S{i}] {ref.title or ref.source_record_id}: {ref.excerpt[:220]}" for i, ref in enumerate(refs[:3], 1))
            return f"Answer generation was unavailable. Retrieved evidence: {evidence}", prompt, AgentStatus.PARTIAL, [f"Generator failed: {type(exc).__name__}"]

    def run(self, query: str, *, top_k: int, max_new_tokens: int | None = None) -> dict[str, Any]:
        started = perf_counter()
        planner_execution = self.planner.run(query)
        plan = planner_execution.artifacts["plan"]
        self.validate_plan(plan)
        results: dict[str, AgentResult] = {"query_planning": planner_execution.result}
        selected = set(plan.selected_agents)
        reasons = plan.selection_reasons
        trace: list[AgentTraceEntry] = [AgentTraceEntry(agent_name="query_planning", selected=True,
            reason=reasons["query_planning"], status=AgentStatus.SUCCESS,
            execution_duration_ms=planner_execution.result.execution_duration_ms)]
        base_input = AgentInput(query=query, plan=plan)

        def record(name: str, result: AgentResult):
            results[name] = result
            trace.append(AgentTraceEntry(agent_name=name, selected=name in selected,
                reason=reasons.get(name, "Not selected by the deterministic query plan."), status=result.status,
                source_record_ids=result.source_record_ids, missing_information=result.missing_information,
                warnings=result.warnings, execution_duration_ms=result.execution_duration_ms, error=result.error))

        try:
            retrieval = self.retrieval_agent.run(base_input, top_k=top_k)
        except Exception as exc:
            retrieval = AgentExecution(result=AgentResult(agent_name="retrieval", status=AgentStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}", warnings=["Dependent analysis agents were skipped."]))
        docs = retrieval.artifacts.get("documents", [])
        specialist_docs = [item[0] if isinstance(item, tuple) and len(item) == 2 else item for item in docs]
        record("retrieval", retrieval.result)

        selected_specialists = [name for name in self.SPECIALISTS if name in selected]
        service = {"geographic": self.geo_agent, "correlation": self.correlation_agent, "contextual_risk": self.risk_agent}
        if retrieval.result.status == AgentStatus.FAILED:
            for name in selected_specialists:
                record(name, AgentResult(agent_name=name, status=AgentStatus.SKIPPED,
                    missing_information=["Retrieval dependency failed."], warnings=["Specialist execution skipped."]))
        else:
            specialist_input = AgentInput(query=query, plan=plan, retrieved_documents=specialist_docs, upstream_results={"retrieval": retrieval.result})
            executor = ThreadPoolExecutor(max_workers=max(1, len(selected_specialists)))
            futures = {executor.submit(service[name].run, specialist_input): name for name in selected_specialists}
            done, pending = wait(futures, timeout=self.specialist_timeout)
            for future in done:
                name = futures[future]
                try:
                    record(name, future.result().result)
                except Exception as exc:
                    record(name, AgentResult(agent_name=name, status=AgentStatus.FAILED, error=f"{type(exc).__name__}: {exc}"))
            for future in pending:
                name = futures[future]
                future.cancel()
                record(name, AgentResult(agent_name=name, status=AgentStatus.FAILED,
                    error="TimeoutError: specialist execution exceeded configured timeout.", warnings=["Timed out agent may finish in the background."]))
            executor.shutdown(wait=False, cancel_futures=True)

        response_started = perf_counter()
        answer, prompt, response_status, response_warnings = self._response(query, docs, results, max_new_tokens)
        record("evidence_response", AgentResult(agent_name="evidence_response", status=response_status,
            input_summary={"retrieved_chunks": len(docs)}, output_data={"answer": answer},
            source_record_ids=results.get("retrieval", AgentResult(agent_name="retrieval", status=AgentStatus.PARTIAL)).source_record_ids,
            warnings=response_warnings, execution_duration_ms=(perf_counter() - response_started) * 1000))

        # Keep a predictable ordering in audit traces, including explicit skips.
        order = ["query_planning", "retrieval", *self.SPECIALISTS, "evidence_response"]
        by_name = {entry.agent_name: entry for entry in trace}
        for name in order:
            if name not in by_name:
                by_name[name] = AgentTraceEntry(agent_name=name, selected=False, reason="Not required by this query plan.", status=AgentStatus.SKIPPED)
        trace = [by_name[name] for name in order]
        warnings = [f"{entry.agent_name}: {entry.error}" for entry in trace if entry.error]
        warnings += [f"{entry.agent_name}: {warning}" for entry in trace for warning in entry.warnings]
        partial = any(entry.status in {AgentStatus.PARTIAL, AgentStatus.FAILED, AgentStatus.SKIPPED} and entry.selected for entry in trace)
        execution_trace = ExecutionTrace(plan=plan, entries=trace,
            total_execution_duration_ms=(perf_counter() - started) * 1000, partial_execution=partial, warnings=warnings)
        return {"query": query, "answer": answer, "retrieved_documents": docs, "prompt": prompt,
                "plan": plan.model_dump(mode="json"),
                "agent_results": {key: value.model_dump(mode="json") for key, value in results.items()},
                "execution_trace": execution_trace.model_dump(mode="json"), "warnings": warnings}
