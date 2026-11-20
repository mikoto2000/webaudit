# Provenance and licensing

The standalone Go engine uses the standard library. WebAudit's original 28 signatures and heuristic/statistical layers remain independent of the upstream compatibility outputs.

Version 0.2.0 vendors Aura's 25 signature definitions, UA/method lists, 63 Hub scenario documents (59 HTTP predicates enabled, four Magento application-event rules explicitly unavailable), and sec-lists data. Go predicates reproduce the embedded source expressions rather than mapping them to broad WebAudit categories. The manifest pins commits and SHA-256; source file attribution and full MIT notices accompany the bundle. See THIRD_PARTY_NOTICES.md and audit/upstream/*-LICENSE. No runtime downloads occur.

See upstream-compatibility.md for verified fixture coverage and remaining execution-environment differences. A passing fixture is evidence for that fixture, not proof of equivalence for all possible logs.
