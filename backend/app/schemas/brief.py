from __future__ import annotations

from pydantic import BaseModel, Field


class ObservedFact(BaseModel):
    fact: str = Field(min_length=3, max_length=600)
    alert_ids: list[str] = Field(min_length=1, max_length=20)


class Hypothesis(BaseModel):
    hypothesis: str = Field(min_length=3, max_length=600)
    confidence: float = Field(ge=0, le=1)


class MitreExplanation(BaseModel):
    technique_id: str
    reason: str = Field(max_length=600)
    technique_name: str | None = None


class InvestigationBrief(BaseModel):
    executive_summary: str = Field(min_length=10, max_length=1500)
    observed_facts: list[ObservedFact] = Field(min_length=1, max_length=15)
    hypotheses: list[Hypothesis] = Field(max_length=6)
    why_high_risk: list[str] = Field(max_length=8)
    affected_entities: list[str] = Field(max_length=15)
    mitre_explanation: list[MitreExplanation] = Field(max_length=12)
    investigation_checks: list[str] = Field(min_length=1, max_length=10)
    uncertainties: list[str] = Field(max_length=8)
    overall_confidence: float = Field(ge=0, le=1)


def brief_json_schema() -> dict:
    """Strict JSON schema (all properties required, no extras) accepted by Gemini and Groq strict mode."""

    def obj(props: dict, ) -> dict:
        return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}

    s = {"type": "string"}
    num = {"type": "number"}
    return obj({
        "executive_summary": s,
        "observed_facts": {"type": "array", "items": obj({"fact": s, "alert_ids": {"type": "array", "items": s}})},
        "hypotheses": {"type": "array", "items": obj({"hypothesis": s, "confidence": num})},
        "why_high_risk": {"type": "array", "items": s},
        "affected_entities": {"type": "array", "items": s},
        "mitre_explanation": {"type": "array", "items": obj({"technique_id": s, "reason": s})},
        "investigation_checks": {"type": "array", "items": s},
        "uncertainties": {"type": "array", "items": s},
        "overall_confidence": num,
    })
