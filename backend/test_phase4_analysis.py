import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from app.threat_analysis.analysis_engine import ThreatAnalysisEngine
from app.threat_analysis.correlation import CorrelationConfig, ThreatCorrelationEngine
from app.threat_analysis.priority import (
    ContextualPriorityAssessor,
    PriorityContext,
)


ROOT = Path(__file__).parent
CSV = ROOT / "data/raw/csv/1_otx_threat_intel.csv"
EVAL = ROOT / "data/evaluation/phase4_correlation.json"
AS_OF = datetime(2026, 11, 15, tzinfo=timezone.utc)


def record(record_id, **kwargs):
    return {"record_id": record_id, "title": record_id, **kwargs}


def test_exact_ioc_matches_normalized_hash_domain_and_ip_with_provenance():
    left = record("left", indicators=[
        {"indicator_type": "sha256", "value": "A" * 64},
        {"indicator_type": "domain", "value": "Example.COM."},
        {"indicator_type": "ip", "value": "2001:0db8::1"},
    ])
    right = record("right", indicators=[
        {"indicator_type": "hash", "value": "a" * 64},
        {"indicator_type": "domain", "value": "example.com"},
        {"indicator_type": "ip address", "value": "2001:db8::1"},
    ])
    result = ThreatCorrelationEngine().correlate([left, right])
    assert len(result) == 1
    relation = result[0]
    assert relation.relationship_strength == "strong_evidence"
    assert {entity.entity_type for entity in relation.matched_entities} == {"hash", "domain", "ip"}
    assert {e.source_record_id for e in relation.supporting_evidence} == {"left", "right"}
    assert relation.correlation_confidence > .8


def test_malware_names_and_aliases_match_exactly_not_by_substring():
    engine = ThreatCorrelationEngine()
    match = engine.correlate([
        record("a", malware=[{"name": "Malware-A", "aliases": ["Family Red"]}]),
        record("b", malware=[{"name": "family red"}]),
    ])
    assert match and match[0].relationship_types == ["shared_reported_malware"]
    assert engine.correlate([
        record("a", malware=[{"name": "Zeus"}]),
        record("b", malware=[{"name": "Zeus-like"}]),
    ]) == []


def test_actor_aliases_cve_campaign_and_exact_relationship_types():
    first = record("a", threat_actors=[{"name": "APT28", "aliases": ["Fancy Bear"]}],
                   description="Activity referenced CVE-2025-12345.",
                   raw_metadata={"campaign_name": "Operation Northstar"})
    second = record("b", threat_actors=[{"name": "Fancy Bear"}],
                    description="CVE-2025-12345 was exploited.",
                    raw_metadata={"campaign_name": "operation northstar"})
    relation = ThreatCorrelationEngine().correlate([first, second])[0]
    assert set(relation.relationship_types) == {
        "shared_reported_actor_name_or_alias", "shared_exact_cve_reference",
        "shared_exact_reported_campaign",
    }
    assert {item.factor for item in relation.factor_contributions} >= {
        "shared_actor", "shared_cve", "shared_campaign"
    }


def test_attack_geo_and_time_are_supporting_only_without_anchor():
    engine = ThreatCorrelationEngine()
    left = record("a", attack_techniques=[{"attack_id": "T1059"}],
                  geographic_evidence=[{"country": "India", "role": "target_location", "status": "supported", "evidence_text": "targeted in India"}],
                  created_at="2026-10-01T00:00:00Z")
    right = record("b", attack_techniques=[{"attack_id": "T1059"}],
                   geographic_evidence=[{"country": "India", "role": "victim_location", "status": "supported", "evidence_text": "victims in India"}],
                   created_at="2026-10-05T00:00:00Z")
    assert engine.correlate([left, right]) == []
    anchored = engine.correlate([record("a", vulnerabilities=["CVE-2025-12345"], **{k: v for k, v in left.items() if k not in {"record_id", "title", "vulnerabilities"}}),
                                 record("b", vulnerabilities=["CVE-2025-12345"], **{k: v for k, v in right.items() if k not in {"record_id", "title", "vulnerabilities"}})])[0]
    assert {x.factor for x in anchored.factor_contributions} >= {"shared_cve", "shared_attack_technique", "geographic_overlap", "temporal_proximity"}
    assert "not_campaign_proof" in " ".join(anchored.relationship_types)


def test_ambiguous_geography_and_source_association_never_create_links():
    engine = ThreatCorrelationEngine()
    assert engine.correlate([
        record("a", countries=["India"], geographic_evidence=[{"country": "India", "role": "general_mention", "status": "ambiguous"}]),
        record("b", countries=["India"], geographic_evidence=[{"country": "India", "role": "general_mention", "status": "ambiguous"}]),
    ]) == []


def test_duplicate_source_records_and_pairs_are_deduplicated():
    engine = ThreatCorrelationEngine()
    left = record("same-id", malware=[{"name": "Family X"}])
    duplicate = record("same-id", malware=[{"name": "Family X"}])
    right = record("other", malware=[{"name": "Family X"}])
    results = engine.correlate([left, duplicate, right, right])
    assert len(results) == 1
    assert (results[0].source_record_id, results[0].related_record_id) == ("other", "same-id") or (results[0].source_record_id, results[0].related_record_id) == ("same-id", "other")


def test_correlation_weights_are_configurable_and_validated():
    config = CorrelationConfig(minimum_confidence=.9, temporal_window_days=45)
    assert ThreatCorrelationEngine(config).correlate([
        record("a", malware=[{"name": "X"}]), record("b", malware=[{"name": "X"}])
    ]) == []
    try:
        CorrelationConfig(factor_weights={"shared_ioc": 1.2})
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-range/missing factor weights should fail validation")


def test_high_and_low_contextual_priority_scores_have_factor_explanations():
    assessor = ContextualPriorityAssessor()
    context = PriorityContext(industry="Healthcare", country="India", as_of=AS_OF)
    high = record("high", description="The vulnerability is actively exploited in the wild.",
                  targets={"industries": ["Healthcare"]},
                  geographic_evidence=[{"country": "India", "role": "target_location", "status": "supported", "confidence": .7, "evidence_text": "targets users in India"}],
                  modified_at=AS_OF)
    low = record("low", description="No exploitation has been observed.",
                 targets={"industries": ["Finance"]},
                 geographic_evidence=[{"country": "Canada", "role": "victim_location", "status": "supported", "confidence": .95, "evidence_text": "victims in Canada"}],
                 modified_at="2025-11-15T00:00:00Z")
    high_score = assessor.assess(high, context)
    low_score = assessor.assess(low, context)
    assert high_score.contextual_priority_score == 100
    assert high_score.coverage == 1
    assert low_score.contextual_priority_score == 0
    assert low_score.coverage == 1
    assert "probability" in high_score.score_semantics
    assert all(item.normalized_contribution is not None for item in high_score.factors if item.value is not None)
    assert low_score.factors[0].status == "source_reports_no_exploitation_observed"


def test_missing_data_reduces_coverage_not_safety_score_and_severity_is_excluded():
    assessment = ContextualPriorityAssessor().assess(
        record("missing", description="The source text is too limited to assess activity.",
               targets={"industries": []}, geography={"countries": ["United States"]}),
        PriorityContext(industry="Healthcare", country="United States", as_of=AS_OF),
    )
    assert assessment.contextual_priority_score is None
    assert assessment.coverage == 0
    assert set(assessment.missing_factors) == {"explicit_exploitation_mention", "industry_context_match", "geographic_context_match", "information_recency"}
    assert "threat_severity" in assessment.excluded_unavailable_factors
    assert "retrieval_similarity" in assessment.excluded_unavailable_factors


def test_source_country_association_does_not_satisfy_geographic_context():
    record_with_association_only = record(
        "associated", description="The report describes observed activity.",
        geography={"countries": ["United States"]}, created_at=AS_OF,
        targets={"industries": ["Healthcare"]},
    )
    result = ContextualPriorityAssessor().assess(
        record_with_association_only,
        PriorityContext(industry="Healthcare", country="United States", as_of=AS_OF),
    )
    geo = next(f for f in result.factors if f.factor == "geographic_context_match")
    assert geo.status == "missing" and geo.value is None

    conflicting = {**record_with_association_only, "geographic_evidence": [{
        "country": "India", "role": "target_location", "status": "supported", "evidence_text": "targets in India"
    }]}
    conflict_result = ContextualPriorityAssessor().assess(
        conflicting,
        PriorityContext(industry="Healthcare", country="United States", as_of=AS_OF),
    )
    conflict_geo = next(f for f in conflict_result.factors if f.factor == "geographic_context_match")
    assert conflict_geo.status == "explicit_nonmatch" and conflict_geo.value == 0


def test_attack_enrichment_status_and_geo_confidence_do_not_masquerade_as_priority():
    assessor = ContextualPriorityAssessor()
    base = record("r", description="The vulnerability is actively exploited in the wild.", created_at=AS_OF,
                  targets={"industries": ["Healthcare"]},
                  geographic_evidence=[{"country": "India", "role": "victim_location", "status": "supported", "confidence": .55}])
    context = PriorityContext(industry="Healthcare", country="India", as_of=AS_OF)
    active = assessor.assess({**base, "attack_techniques": [{"attack_id": "T1486", "enrichment_status": "active"}]}, context)
    historical = assessor.assess({**base, "attack_techniques": [{"attack_id": "T1486", "enrichment_status": "historical"}], "geographic_evidence": [{"country": "India", "role": "victim_location", "status": "supported", "confidence": .99}]}, context)
    assert active.contextual_priority_score == historical.contextual_priority_score
    assert "attack_technique_severity" in active.excluded_unavailable_factors


def test_industry_context_changes_relevance_not_intrinsic_record_severity():
    assessor = ContextualPriorityAssessor()
    item = record("industry", description="The vulnerability is actively exploited in the wild.",
                  created_at=AS_OF, targets={"industries": ["Healthcare"]})
    healthcare = assessor.assess(item, PriorityContext(industry="Healthcare", as_of=AS_OF))
    finance = assessor.assess(item, PriorityContext(industry="Finance", as_of=AS_OF))
    assert healthcare.contextual_priority_score > finance.contextual_priority_score
    assert next(f for f in finance.factors if f.factor == "industry_context_match").status == "explicit_nonmatch"


def test_orchestrator_keeps_pair_correlation_and_priority_separate():
    output = ThreatAnalysisEngine().analyze([
        record("a", malware=[{"name": "X"}], description="Actively exploited in the wild.", created_at=AS_OF),
        record("b", malware=[{"name": "X"}], created_at=AS_OF),
    ], PriorityContext(as_of=AS_OF))
    assert len(output["correlations"]) == 1
    assert len(output["contextual_priorities"]) == 2
    assert "correlation_confidence" in output["correlations"][0]
    assert "contextual_priority_score" in output["contextual_priorities"][0]
    assert "correlation_confidence" not in output["contextual_priorities"][0]


def test_actual_otx_pair_evaluation_and_false_positive_behavior():
    labels = json.loads(EVAL.read_text(encoding="utf-8"))
    frame = pd.read_csv(CSV).fillna("")
    source_docs = {}
    from app.rag.loader import load_canonical_cti_csv
    for document in load_canonical_cti_csv(CSV):
        record_id = document.metadata["source_record_id"]
        source_docs.setdefault(record_id, json.loads(document.metadata["canonical_cti"]))
    tp = fp = fn = tn = 0
    for pair in labels["pairs"]:
        assert pair["left_id"] in source_docs and pair["right_id"] in source_docs
        related = ThreatCorrelationEngine().correlate([source_docs[pair["left_id"]], source_docs[pair["right_id"]]])
        predicted = bool(related)
        if predicted and pair["should_link"]:
            tp += 1
        elif predicted:
            fp += 1
        elif pair["should_link"]:
            fn += 1
        else:
            tn += 1
        if pair["should_link"]:
            assert pair["expected_relationship"] in {value for row in related for value in row.relationship_types}
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    print({"reviewed_pairs": len(labels["pairs"]), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall})
    assert (tp, fp, fn, tn) == (2, 0, 0, 1)


def test_manually_reviewed_actual_priority_examples():
    labels = json.loads((ROOT / "data/evaluation/phase4_priority_examples.json").read_text(encoding="utf-8"))
    from app.rag.loader import load_canonical_cti_csv
    records = {}
    for document in load_canonical_cti_csv(CSV):
        records.setdefault(document.metadata["source_record_id"], json.loads(document.metadata["canonical_cti"]))
    as_of = datetime.fromisoformat(labels["as_of"].replace("Z", "+00:00"))
    assessor = ContextualPriorityAssessor()
    for example in labels["examples"]:
        source_id = example["source_record_id"]
        assert source_id in records
        context = PriorityContext(**example["context"], as_of=as_of)
        assessment = assessor.assess(records[source_id], context)
        actual = {factor.factor: factor.status for factor in assessment.factors}
        assert {key: actual[key] for key in example["expected_factor_states"]} == example["expected_factor_states"]
        assert assessment.contextual_priority_score is not None
