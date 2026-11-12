"""Standards alignment mapping for ChainProof actions.

ChainProof is aligned with, not compliant to, the following frameworks.
Exact conformance would require third-party assessment against each document.
"""

# ISO/IEC 27037:2012 covers identification, collection, acquisition and
# preservation only. Analysis, evaluation, reporting and testimony belong to
# related standards (ISO/IEC 27041, 27042, 27043).
ISO_IEC_27037 = {
    "identification": "Recognizing and selecting potential evidence sources.",
    "collection": "Gathering evidence while preserving integrity.",
    "acquisition": "Creating a bit-for-bit forensic image or copy.",
    "preservation": "Protecting evidence from alteration or loss.",
}

# ENFSI best-practice principles for digital evidence examination.
ENFSI = {
    "integrity": "Evidence must remain unaltered from collection to presentation.",
    "documentation": "Every action on evidence must be recorded contemporaneously.",
    "traceability": "Each evidence item must be traceable to its source.",
    "reproducibility": "A competent examiner must be able to repeat the process.",
    "independence": "Examinations must be objective and free from bias.",
}

# Higher-level phases handled by ChainProof but outside ISO/IEC 27037's scope.
ADDITIONAL_PHASES = {
    "analysis": "Examining evidence to draw conclusions (ISO/IEC 27041/27042).",
    "evaluation": "Assessing findings against the case context (ISO/IEC 27042).",
    "reporting": "Documenting methods and results (ISO/IEC 27042).",
    "testimony": "Presenting evidence and findings (ISO/IEC 27043).",
}

ACTION_STANDARDS_MAP = {
    "CASE_INITIALIZED": ["documentation"],
    "EVIDENCE_ADDED": ["identification", "collection", "preservation"],
    "HASH_VERIFIED": ["preservation", "integrity"],
    "ACCESS": ["documentation", "traceability"],
    "TRANSFER": ["documentation", "traceability", "preservation"],
    "ANALYSIS": ["analysis", "evaluation"],
    "RELEASE": ["documentation", "traceability"],
    "REPORT_EXPORTED": ["reporting"],
}

STANDARDS_NOTE = (
    "ChainProof is aligned with ISO/IEC 27037 (identification, collection, "
    "acquisition and preservation of digital evidence) and ENFSI best-practice "
    "principles (integrity, documentation, traceability, reproducibility, "
    "independence). Higher-level phases (analysis, evaluation, reporting, "
    "testimony) map to ISO/IEC 27041, 27042 and 27043. Hash-chained, signed "
    "audit entries make log tampering detectable, supporting the documentation "
    "and integrity requirements of both frameworks."
)

DISCLAIMER = (
    "This tool is a student/educational prototype. It is not a certified "
    "forensic product and makes no claim of legal admissibility or formal "
    "standards compliance."
)
