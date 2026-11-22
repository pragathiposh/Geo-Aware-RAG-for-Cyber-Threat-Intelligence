"""Conservative, deterministic location evidence extraction from CTI text."""

from __future__ import annotations

import re

from app.geo.geo_resolver import GeoResolver
from app.threat_analysis.cti_schema import (
    CTIGeographicEvidence,
    GeographicEvidenceRole as Role,
    GeographicEvidenceStatus as Status,
)


REGION_ALIASES = {
    "north america": "North America", "europe": "Europe",
    "south asia": "South Asia", "east asia": "East Asia",
    "southeast asia": "Southeast Asia", "middle east": "Middle East",
    "oceania": "Oceania", "asia-pacific": "Asia-Pacific",
    "asia pacific": "Asia-Pacific", "apac": "Asia-Pacific",
    "south america": "South America", "central america": "Central America",
    "africa": "Africa", "asia": "Asia",
}


class GeographicEvidenceExtractor:
    """Extract country/region mentions and classify only explicit roles."""

    METHOD = "rule_based_v1"
    _role_rules = (
        (Role.VICTIM_LOCATION, re.compile(r"\b(?:victims?|customers?|users?)\b.{0,100}\b(?:based|located|residing)\s+in\s+(?:the\s+)?$|\b(?:victims?|customers?)\s+in\s+(?:the\s+)?$", re.I), .90),
        (Role.INCIDENT_LOCATION, re.compile(r"\b(?:incidents?|ransomware attacks?|breaches?|cases?)\s+in\s+$|\b(?:occurred|took place)\s+in\s+$", re.I), .91),
        (Role.TARGET_LOCATION, re.compile(r"\b(?:target(?:s|ed|ing)?|campaigns?|operations?|compromised)\b.{0,120}\b(?:in|across|against)\s+$|\b(?:targeting|affecting)\s+(?:users?|organizations?|entities|businesses)\s+in\s+$", re.I), .88),
        (Role.CLAIMED_ACTOR_ORIGIN, re.compile(r"\b(?:based|originating)\s+in\s+$|\b(?:actors?|group|threat actor)\s+from\s+$", re.I), .82),
        (Role.INFRASTRUCTURE_LOCATION, re.compile(r"\b(?:servers?|infrastructure|proxy|C2|command-and-control)\b.{0,90}\b(?:hosted|located|deployed|based)\s+in\s+$|\b(?:cloud server|server)\s+in\s+$", re.I), .86),
    )
    _negation = re.compile(r"\b(?:no|not|never|neither|without|did not|does not|was not|were not)\b", re.I)

    def __init__(self) -> None:
        aliases = dict(GeoResolver.COUNTRY_ALIASES)
        aliases.update({
            "united states of america": "United States", "america": "United States",
            "north korea": "North Korea", "south korea": "South Korea",
            "republic of korea": "South Korea", "russia": "Russia",
            "russian federation": "Russia", "ukraine": "Ukraine",
            "brazil": "Brazil", "mexico": "Mexico", "vietnam": "Vietnam",
            "turkey": "Türkiye", "türkiye": "Türkiye", "azerbaijan": "Azerbaijan",
            "mongolia": "Mongolia", "finland": "Finland", "pakistan": "Pakistan",
            "indonesia": "Indonesia", "philippines": "Philippines", "poland": "Poland",
            "netherlands": "Netherlands", "sweden": "Sweden", "norway": "Norway",
            "belgium": "Belgium", "italy": "Italy", "ireland": "Ireland",
            "afghanistan": "Afghanistan", "argentina": "Argentina", "colombia": "Colombia",
            "chile": "Chile", "taiwan": "Taiwan", "israel": "Israel",
            "indian demonym": "India",
            "british indian ocean territory": "British Indian Ocean Territory",
        })
        self.aliases = aliases
        self._locations = self._compile_locations()

    def _compile_locations(self):
        patterns = []
        for alias, country in self.aliases.items():
            # `US` is a common English pronoun; accept only uppercase token or dotted abbreviation.
            if alias == "us":
                pattern = r"(?<!\w)(?:US|U\.S\.)(?!\w)"
            elif alias == "u.s.":
                pattern = r"(?<!\w)U\.S\.(?!\w)"
            elif alias == "u.s.a.":
                pattern = r"(?<!\w)U\.S\.A\.(?!\w)"
            elif alias == "u.k.":
                pattern = r"(?<!\w)U\.K\.(?!\w)"
            elif alias == "u.a.e.":
                pattern = r"(?<!\w)U\.A\.E\.(?!\w)"
            elif alias == "indian demonym":
                pattern = r"(?<!\w)Indian(?=\s+(?:government|entities|organizations|firms|users|companies|defense|defence))"
            else:
                pattern = rf"(?<!\w){re.escape(alias)}(?!\w)"
            flags = 0 if alias == "us" else re.I
            patterns.append((len(alias), re.compile(pattern, flags), country))
        for alias, region in REGION_ALIASES.items():
            patterns.append((len(alias), re.compile(rf"(?<!\w){re.escape(alias)}(?!\w)", re.I), region))
        return sorted(patterns, reverse=True, key=lambda item: item[0])

    @staticmethod
    def _sentences(description: str):
        for match in re.finditer(r"[^.!?\n]+(?:[.!?]|$)", description):
            start, end = match.span()
            text = match.group().strip()
            if text:
                left = len(match.group()) - len(match.group().lstrip())
                yield start + left, end, text

    def extract(self, description: str, source_record_id: str) -> list[CTIGeographicEvidence]:
        if not description or not source_record_id:
            return []
        results = []
        for sentence_start, sentence_end, sentence in self._sentences(description):
            occupied: list[tuple[int, int]] = []
            mentions = []
            for _, pattern, canonical in self._locations:
                for match in pattern.finditer(sentence):
                    if any(match.start() < end and match.end() > start for start, end in occupied):
                        continue
                    occupied.append(match.span())
                    is_region = canonical in set(REGION_ALIASES.values())
                    mentions.append((match.start(), match.end(), match.group(), None if is_region else canonical, canonical if is_region else GeoResolver.COUNTRY_REGIONS.get(canonical)))
            previous = None
            for start, end, surface, country, region in sorted(mentions):
                prefix = sentence[:start]
                suffix = sentence[end:]
                status, role, confidence, uncertainty = Status.AMBIGUOUS, Role.GENERAL_MENTION, .55, "Mention alone does not establish a geographic role."
                # Negation is conservative: only nearby assertion context before the place.
                if self._negation.search(prefix[-90:]):
                    status, confidence = Status.NEGATED, .30
                    uncertainty = "Nearby negation prevents treating this as supported location evidence."
                else:
                    for candidate_role, cue, score in self._role_rules:
                        actor_suffix = re.match(r"\s*[- ]based\s+(?:threat\s+)?(?:actor|group)", suffix, re.I)
                        victim_suffix = re.match(r"\s+(?:and\s+)?(?:government\s+)?(?:entities|organizations|users|victims|businesses)", suffix, re.I)
                        infrastructure_suffix = re.match(r"\s+(?:based|hosted|located)", suffix, re.I)
                        coordinated_list = False
                        if candidate_role == Role.CLAIMED_ACTOR_ORIGIN:
                            origin = re.search(r"\b(?:actors?|groups?|threat actors?)\s+from\s+([\w .-]+)", sentence[:start], re.I)
                            if origin:
                                between = sentence[origin.end(1):start]
                                coordinated_list = bool(re.fullmatch(r"[\s,]*(?:(?:and|or)\s+)?", between, re.I))
                        if cue.search(prefix[-150:]) or coordinated_list or (candidate_role == Role.CLAIMED_ACTOR_ORIGIN and actor_suffix) or (candidate_role == Role.TARGET_LOCATION and victim_suffix and re.search(r"\btarget(?:s|ed|ing)?\b", prefix[-120:], re.I)) or (candidate_role == Role.INFRASTRUCTURE_LOCATION and infrastructure_suffix and re.search(r"\b(?:server|infrastructure|proxy|C2)\b", prefix[-100:], re.I)):
                            role, status, confidence = candidate_role, Status.SUPPORTED, score
                            uncertainty = "Source wording is extracted as a claim and is not independently verified."
                            if role == Role.CLAIMED_ACTOR_ORIGIN:
                                uncertainty = "Reported actor-origin attribution; not an incident location or independently verified origin."
                            break
                if role == Role.INFRASTRUCTURE_LOCATION:
                    uncertainty = "Reported infrastructure location; not attacker origin and not an incident/victim location."
                if previous:
                    prior_end, prior_role, prior_status, prior_confidence, prior_uncertainty = previous
                    between = sentence[prior_end:start]
                    if re.fullmatch(r"[\s,]*(?:(?:and|or)\s+)?", between, re.I):
                        role, status, confidence, uncertainty = prior_role, prior_status, prior_confidence, prior_uncertainty
                evidence = sentence
                results.append(CTIGeographicEvidence(
                    country=country, region=region, role=role, evidence_text=evidence,
                    start_char=sentence_start + start, end_char=sentence_start + end,
                    source_record_id=source_record_id, extraction_method=self.METHOD,
                    confidence=confidence, status=status, provenance="source_description",
                    uncertainty=uncertainty,
                ))
                previous = (end, role, status, confidence, uncertainty)
        return results
