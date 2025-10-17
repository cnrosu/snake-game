"""Utilities for evaluating Wi-Fi security posture and rendering a risk card.

This module encodes the rubric provided in the task description.  It accepts
normalized inputs describing an interface observation, access point
capabilities, passphrase metrics, and modifier flags, and it produces the
formatted card required for reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Optional, Sequence


class SecurityCategory(Enum):
    """Represents the broad Wi-Fi security posture of an SSID."""

    OPEN = "Open Network"
    WEP_TKIP = "WEP/TKIP"
    WPA2_PSK = "WPA2-Personal (CCMP)"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    WPA3_PSK = "WPA3-Personal (SAE)"
    WPA3_ENTERPRISE = "WPA3-Enterprise (192-bit)"

    @property
    def matrix_row(self) -> str:
        if self in {SecurityCategory.OPEN, SecurityCategory.WEP_TKIP}:
            return "Open/WEP/TKIP"
        if self is SecurityCategory.WPA2_PSK:
            return "WPA2-PSK"
        if self is SecurityCategory.WPA2_ENTERPRISE:
            return "WPA2-Enterprise"
        if self is SecurityCategory.WPA3_PSK:
            return "WPA3-Personal"
        return "WPA3-Enterprise"

    @property
    def display_name(self) -> str:
        return self.value


BASE_ENCRYPTION_SCORES = {
    SecurityCategory.OPEN: 4,
    SecurityCategory.WEP_TKIP: 4,
    SecurityCategory.WPA2_PSK: 2,
    SecurityCategory.WPA2_ENTERPRISE: 3,
    SecurityCategory.WPA3_PSK: 3,
    SecurityCategory.WPA3_ENTERPRISE: 4,
}

SEVERITY_MATRIX = {
    "Open/WEP/TKIP": {1: "Critical", 2: "Critical", 3: "Critical", 4: "High"},
    "WPA2-PSK": {1: "High", 2: "High", 3: "Medium", 4: "Low"},
    "WPA2-Enterprise": {1: "High", 2: "Medium", 3: "Low", 4: "Low"},
    "WPA3-Personal": {1: "High", 2: "Medium", 3: "Low", 4: "Low"},
    "WPA3-Enterprise": {1: "Medium", 2: "Low", 3: "Low", 4: "Low"},
}

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def _severity_worse(value: str) -> str:
    try:
        idx = SEVERITY_ORDER.index(value)
    except ValueError:
        return value
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


def _format_bool(value: Optional[bool]) -> str:
    if value is None:
        return "Unknown"
    return "Yes" if value else "No"


def _format_on_off(value: Optional[bool]) -> str:
    if value is None:
        return "Unknown"
    return "On" if value else "Off"


def format_machine_bool(value: Optional[bool]) -> str:
    if value is None:
        return "Unknown"
    return str(bool(value)).lower()


@dataclass
class InterfaceObservation:
    ssid: str
    authentication: str
    cipher: str
    pmf: str = "Unknown"


@dataclass
class AccessPointCapabilities:
    wpa3_support: Optional[bool] = None
    wpa2_support: Optional[bool] = None
    transition_mode: Optional[bool] = None
    pmf_policy: str = "Unknown"


@dataclass
class ClientAssociation:
    actual_method: str


@dataclass
class PassphrasePenalty:
    description: str
    severity: float = 1.0


@dataclass
class PassphraseMetrics:
    entropy_bits: float
    length: int
    classes_used: Sequence[str]
    penalties: Iterable[PassphrasePenalty] = field(default_factory=list)


@dataclass
class RiskFlags:
    wps_enabled: Optional[bool] = None
    transition_mode: Optional[bool] = None
    pmf_status: str = "Unknown"


@dataclass
class PassphraseAssessment:
    score: int
    label: str
    rationale: str
    penalties_applied: List[str]


@dataclass
class EncryptionAssessment:
    score: int
    category: SecurityCategory
    category_after_modifiers: SecurityCategory
    rationale: str
    modifiers_applied: List[str]


def determine_security_category(
    observation: InterfaceObservation, association: ClientAssociation
) -> SecurityCategory:
    actual = association.actual_method.lower()
    auth = observation.authentication.lower()
    cipher = observation.cipher.lower()

    if "wpa3" in actual and "enterprise" in actual:
        return SecurityCategory.WPA3_ENTERPRISE
    if "suite-b" in actual or "192" in actual:
        return SecurityCategory.WPA3_ENTERPRISE
    if "wpa3" in actual or "sae" in actual:
        return SecurityCategory.WPA3_PSK
    if "wpa2" in actual and "enterprise" in actual:
        return SecurityCategory.WPA2_ENTERPRISE
    if "802.1x" in actual:
        return SecurityCategory.WPA2_ENTERPRISE
    if "wpa2" in actual and ("personal" in actual or "psk" in actual):
        return SecurityCategory.WPA2_PSK
    if "wpa" in actual and "psk" in actual and "tkip" in cipher:
        return SecurityCategory.WEP_TKIP
    if "wep" in actual or "wep" in auth or "wep" in cipher:
        return SecurityCategory.WEP_TKIP
    if "tkip" in cipher:
        return SecurityCategory.WEP_TKIP
    if "open" in actual or "none" in cipher:
        return SecurityCategory.OPEN

    # Fall back to authentication string if the association string is not
    # descriptive.
    if "wpa3" in auth and "enterprise" in auth:
        return SecurityCategory.WPA3_ENTERPRISE
    if "wpa3" in auth:
        return SecurityCategory.WPA3_PSK
    if "wpa2" in auth and "enterprise" in auth:
        return SecurityCategory.WPA2_ENTERPRISE
    if "wpa2" in auth:
        return SecurityCategory.WPA2_PSK
    if "wpa" in auth and "tkip" in cipher:
        return SecurityCategory.WEP_TKIP
    if "open" in auth:
        return SecurityCategory.OPEN

    return SecurityCategory.WPA2_PSK


def assess_passphrase(metrics: PassphraseMetrics) -> PassphraseAssessment:
    entropy = metrics.entropy_bits
    penalties = list(metrics.penalties)
    if entropy >= 96:
        base_score = 4
        base_label = "Very Strong"
    elif entropy >= 72:
        base_score = 3
        base_label = "Strong"
    elif entropy >= 60:
        base_score = 2
        base_label = "Average"
    else:
        base_score = 1
        base_label = "Weak"

    score_value = float(base_score)
    penalties_applied: List[str] = []
    for penalty in penalties:
        score_value -= penalty.severity
        penalties_applied.append(penalty.description)

    score_value = max(1.0, score_value)
    final_score = int(score_value // 1)
    if score_value % 1 == 0:
        final_score = int(score_value)
    final_score = max(1, min(4, final_score))

    label_lookup = {1: "Weak", 2: "Average", 3: "Strong", 4: "Very Strong"}
    final_label = label_lookup[final_score]

    if penalties_applied:
        rationale = (
            f"Started at {base_label} ({entropy:.1f} bits) but penalties lowered it to "
            f"{final_label}."
        )
    else:
        rationale = f"Entropy {entropy:.1f} bits yields a {final_label} rating."

    return PassphraseAssessment(
        score=final_score,
        label=final_label,
        rationale=rationale,
        penalties_applied=penalties_applied,
    )


def assess_encryption(
    category: SecurityCategory,
    modifiers: RiskFlags,
    transition_implies_wpa2_psk: bool,
) -> EncryptionAssessment:
    base_score = BASE_ENCRYPTION_SCORES[category]
    modifiers_applied: List[str] = []
    effective_category = category
    transition_penalized = False

    def degrade(reason: str) -> None:
        nonlocal effective_category, base_score
        modifiers_applied.append(reason)
        base_score = max(1, base_score - 1)
        effective_category = {
            SecurityCategory.WPA3_ENTERPRISE: SecurityCategory.WPA3_PSK,
            SecurityCategory.WPA3_PSK: SecurityCategory.WPA2_PSK,
            SecurityCategory.WPA2_ENTERPRISE: SecurityCategory.WPA2_PSK,
            SecurityCategory.WPA2_PSK: SecurityCategory.OPEN,
            SecurityCategory.WEP_TKIP: SecurityCategory.OPEN,
            SecurityCategory.OPEN: SecurityCategory.OPEN,
        }[effective_category]

    if transition_implies_wpa2_psk and effective_category == SecurityCategory.WPA3_PSK:
        degrade("Client associated via WPA2 during WPA3 transition")
        transition_penalized = True

    if modifiers.transition_mode and not transition_penalized:
        degrade("Transition mode lowers effective security tier")

    pmf_state = (modifiers.pmf_status or "").lower()
    pmf_lowered = pmf_state in {"optional", "disabled"}
    if pmf_lowered:
        degrade("PMF not enforced")

    if modifiers.wps_enabled:
        degrade("WPS enabled on PSK network")

    rationale_parts = [f"Base score {BASE_ENCRYPTION_SCORES[category]} for {category.display_name}"]
    if modifiers_applied:
        rationale_parts.append(
            "; ".join(
                ["modifiers applied: " + ", ".join(modifiers_applied)]
            )
        )
    rationale = "; ".join(rationale_parts)

    return EncryptionAssessment(
        score=base_score,
        category=category,
        category_after_modifiers=effective_category,
        rationale=rationale,
        modifiers_applied=modifiers_applied,
    )


def determine_severity(
    encryption: EncryptionAssessment,
    passphrase: PassphraseAssessment,
    modifiers: RiskFlags,
) -> str:
    row = encryption.category_after_modifiers.matrix_row
    severity = SEVERITY_MATRIX[row][passphrase.score]

    pmf_state = (modifiers.pmf_status or "").lower()
    for flag, active in (
        ("transition", modifiers.transition_mode),
        ("pmf", pmf_state in {"optional", "disabled"}),
        ("wps", modifiers.wps_enabled),
    ):
        if active:
            severity = _severity_worse(severity)

    return severity


def build_title(
    encryption: EncryptionAssessment, passphrase: PassphraseAssessment, modifiers: RiskFlags
) -> str:
    pmf_descriptor = modifiers.pmf_status.title() if modifiers.pmf_status else "Unknown"
    method_display = encryption.category_after_modifiers.display_name
    if encryption.category_after_modifiers is SecurityCategory.WPA3_PSK:
        method_display = f"WPA3-Personal (SAE, PMF {pmf_descriptor.lower()})"
    elif encryption.category_after_modifiers is SecurityCategory.WPA3_ENTERPRISE:
        method_display = f"WPA3-Enterprise (PMF {pmf_descriptor.lower()})"
    elif encryption.category_after_modifiers is SecurityCategory.WPA2_PSK:
        method_display = f"WPA2-Personal (CCMP)"
    elif encryption.category_after_modifiers is SecurityCategory.WPA2_ENTERPRISE:
        method_display = "WPA2-Enterprise"
    elif encryption.category_after_modifiers in {SecurityCategory.OPEN, SecurityCategory.WEP_TKIP}:
        method_display = "Open Network"
    return f"Wi-Fi: {method_display}; Passphrase {passphrase.label} → {{severity}}"


def summarize(
    encryption: EncryptionAssessment,
    passphrase: PassphraseAssessment,
    entropy_bits: float,
    severity: str,
) -> str:
    return (
        f"{encryption.category_after_modifiers.matrix_row} exposure with a {passphrase.label} "
        f"passphrase ({entropy_bits:.1f} bits) results in {severity} risk."
    )


def format_penalty(penalties: Sequence[str]) -> str:
    if not penalties:
        return "No"
    reasons = "; ".join(penalties)
    return f"Yes — {reasons}"


def render_wifi_risk_card(
    observation: InterfaceObservation,
    ap_capabilities: AccessPointCapabilities,
    association: ClientAssociation,
    passphrase_metrics: PassphraseMetrics,
    risk_flags: RiskFlags,
) -> str:
    category = determine_security_category(observation, association)
    transition_wpa2 = (
        bool(risk_flags.transition_mode)
        and "wpa2" in association.actual_method.lower()
        and "wpa3" in observation.authentication.lower()
    )

    passphrase_assessment = assess_passphrase(passphrase_metrics)
    encryption_assessment = assess_encryption(category, risk_flags, transition_wpa2)
    severity = determine_severity(encryption_assessment, passphrase_assessment, risk_flags)

    title_template = build_title(encryption_assessment, passphrase_assessment, risk_flags)
    title = title_template.format(severity=severity)
    summary = summarize(
        encryption_assessment,
        passphrase_assessment,
        passphrase_metrics.entropy_bits,
        severity,
    )

    pattern_penalty = format_penalty(passphrase_assessment.penalties_applied)

    modifiers_list = (
        encryption_assessment.modifiers_applied if encryption_assessment.modifiers_applied else ["None"]
    )
    modifiers_text = ", ".join(modifiers_list)

    card_lines = [
        f"Title:\n{title}",
        "",
        f"Summary (one line):\n{summary}",
        "",
        "Evidence (only operator-useful lines):",
        "Interface:",
        f'SSID: "{observation.ssid}"',
        f"Authentication: {observation.authentication}",
        f"Cipher: {observation.cipher}",
        f"PMF: {observation.pmf}",
        "AP Capabilities (scan):",
        f"WPA3 support: {_format_bool(ap_capabilities.wpa3_support)}",
        f"WPA2 support: {_format_bool(ap_capabilities.wpa2_support)}",
        f"Transition mode: {_format_bool(ap_capabilities.transition_mode)}",
        f"PMF policy: {ap_capabilities.pmf_policy}",
        "Client Association:",
        f"Actual method used: {association.actual_method}",
        "Passphrase Metrics (never print the passphrase):",
        f"EntropyBits: {passphrase_metrics.entropy_bits:.1f}",
        f"Length: {passphrase_metrics.length}",
        "ClassesUsed: ["
        + ", ".join(passphrase_metrics.classes_used)
        + "]",
        f"PatternPenaltyApplied: {pattern_penalty}",
        f"FinalRating: {passphrase_assessment.label}",
        "Risk Modifiers:",
        f"WPS: {_format_on_off(risk_flags.wps_enabled)}",
        f"TransitionMode: {_format_on_off(risk_flags.transition_mode)}",
        f"PMF: {risk_flags.pmf_status}",
        "Determination:",
        f"EncryptionScore (E): {encryption_assessment.score} with {encryption_assessment.rationale}",
        f"PassphraseScore (P): {passphrase_assessment.score} with {passphrase_assessment.rationale}",
        f"Modifiers applied: {modifiers_text}",
        f"MatrixResult: {severity}",
        "Recommended Actions (priority order):",
        "- Prefer WPA3-Personal (SAE) or WPA2/3-Enterprise (802.1X) with PMF Required.",
        "- If remaining on PSK: enforce >=16 truly random characters (target >=96-bit entropy), rotate PSK, disable WPS.",
        "- If transition mode is required for legacy, isolate legacy devices on a separate SSID/VLAN with stricter egress controls and plan a deprecation timeline.",
        "",
        "Machine-friendly fields (example):",
        "Category: Network/Security",
        "Subcategory: Wi-Fi",
        f'SSID: "{observation.ssid}"',
        f"SecurityMethod: {encryption_assessment.category_after_modifiers.matrix_row}",
        f"Cipher: {observation.cipher}",
        f"PMF: {risk_flags.pmf_status}",
        f"TransitionMode: {format_machine_bool(risk_flags.transition_mode)}",
        f"WPS: {format_machine_bool(risk_flags.wps_enabled)}",
        f"Passphrase.EntropyBits: {passphrase_metrics.entropy_bits:.1f}",
        f"Passphrase.Length: {passphrase_metrics.length}",
        "Passphrase.Classes: ["
        + ", ".join(passphrase_metrics.classes_used)
        + "]",
        f"Passphrase.PatternPenalty: {format_machine_bool(bool(passphrase_assessment.penalties_applied))}",
        f"Passphrase.FinalRating: {passphrase_assessment.label}",
        f"Scores.E: {encryption_assessment.score}",
        f"Scores.P: {passphrase_assessment.score}",
        f"Severity: {severity}",
    ]

    return "\n".join(card_lines)

