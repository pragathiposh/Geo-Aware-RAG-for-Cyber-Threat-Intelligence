
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ConfidenceLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ImpactDirection(str, Enum):
    INCREASES_RISK = "increases_risk"
    DECREASES_RISK = "decreases_risk"
    NEUTRAL = "neutral"


class TargetContext(BaseModel):
    target_country: Optional[str] = None
    target_region: Optional[str] = None
    target_industry: Optional[str] = None
    critical_asset_tier: int = Field(default=2, ge=1, le=4)
    existing_controls_score: float = Field(default=0.0, ge=0.0, le=1.0)
    network_exposure: float = Field(default=0.5, ge=0.0, le=1.0)


class ThreatInput(BaseModel):
    pulse_id: str
    title: str
    description: str
    author: Optional[str] = None
    tlp: Optional[str] = None
    malware_families: list[str] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)
    industries: list[str] = Field(default_factory=list)
    indicators_count: float = Field(default=0.0, ge=0.0)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    is_actively_exploited: bool = False
    cve_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: Optional[str] = None


class ConfidenceBreakdown(BaseModel):
    data_completeness: float = Field(ge=0.0, le=1.0)
    source_reliability: float = Field(ge=0.0, le=1.0)
    model_certainty: float = Field(ge=0.0, le=1.0)
    context_alignment: float = Field(ge=0.0, le=1.0)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel
    evaluation_notes: list[str] = Field(default_factory=list)


class FeatureImpact(BaseModel):
    feature_name: str
    display_name: str
    feature_value: float
    impact_score: float
    direction: ImpactDirection
    description: str


class RiskExplanation(BaseModel):
    summary: str
    top_risk_drivers: list[FeatureImpact] = Field(default_factory=list)
    top_mitigating_factors: list[FeatureImpact] = Field(default_factory=list)
    geo_explanation: str = ""
    sector_explanation: str = ""
    recommended_actions: list[str] = Field(default_factory=list)


class RiskPredictionOutput(BaseModel):
    pulse_id: str
    title: str
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    ml_probability: float = Field(ge=0.0, le=1.0)
    heuristic_score: float = Field(ge=0.0, le=100.0)
    geo_relevance_multiplier: float = Field(ge=0.0)
    industry_relevance_multiplier: float = Field(ge=0.0)
    confidence: ConfidenceBreakdown
    explanation: RiskExplanation
    features: dict[str, float] = Field(default_factory=dict)
    assessed_at: str


class RiskAssessmentRequest(BaseModel):
    threat: ThreatInput
    target_context: Optional[TargetContext] = None


class BatchRiskAssessmentRequest(BaseModel):
    threats: list[ThreatInput] = Field(min_length=1)
    target_context: Optional[TargetContext] = None


class BatchRiskAssessmentResponse(BaseModel):
    total_assessed: int
    risk_distribution: dict[str, int]
    average_risk_score: float
    results: list[RiskPredictionOutput]


class PulseAssessmentRequest(BaseModel):
    pulse_id: str
    target_context: Optional[TargetContext] = None


class ModelInfoResponse(BaseModel):
    model_name: str
    model_version: str
    status: str
    num_features: int
    feature_names: list[str]
    feature_importances: dict[str, float] = Field(default_factory=dict)
    training_samples: int
    last_trained_at: Optional[str] = None


class RiskFactorsResponse(BaseModel):
    factors: list[str]
    scoring_weights: dict[str, float]
