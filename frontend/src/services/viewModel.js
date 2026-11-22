const list = (value) => Array.isArray(value) ? value : value == null ? [] : [value];

export function buildDashboardView(response) {
  const agentResults = response?.agent_results ?? {};
  const traceEntries = response?.execution_trace?.entries ?? [];
  const geo = response?.geographic_findings ?? {};
  const geoEvidence = geo.supported_location_evidence ?? [];
  const countryCounts = geo.aggregation?.evidence_supported_counts ?? {};
  const associationCounts = geo.aggregation?.source_association_counts ?? {};
  const relationships = response?.threat_correlations ?? [];
  const priorities = response?.contextual_priorities ?? [];
  const sources = response?.sources ?? [];
  const warnings = [
    ...(response?.warnings ?? []),
    ...(response?.missing_evidence ?? []),
  ];
  for (const result of Object.values(agentResults)) {
    warnings.push(...(result?.missing_information ?? []));
  }
  return {
    query: response?.query ?? "",
    answer: response?.answer ?? "The API did not return an answer.",
    partial: Boolean(response?.partial),
    geographic: {
      evidence: geoEvidence,
      evidenceCounts: countryCounts,
      sourceAssociationCounts: associationCounts,
      unknownSourceIds: geo.aggregation?.unknown_or_unsupported_source_record_ids ?? [],
    },
    relationships,
    priorities,
    sources: sources.map((source) => ({
      ...source,
      attack_ids: list(source.attack_ids),
      attack_techniques: list(source.attack_techniques),
      malware_families: list(source.malware_families),
      industries: list(source.industries),
      countries: list(source.country_associations ?? source.countries),
      geographic_evidence: list(source.geographic_evidence),
    })),
    trace: traceEntries,
    warnings: [...new Set(warnings.filter(Boolean))],
    plan: response?.execution_plan ?? {},
  };
}
