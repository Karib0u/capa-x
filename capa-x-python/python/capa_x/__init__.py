"""In-process Python binding for capa-x.

Load a rule set once, scan as many samples as you like::

    import capa_x

    rules = capa_x.Rules.from_directory("rules")
    result = capa_x.analyze("sample.exe", rules)
    print(result["rules"].keys())

``analyze()`` returns upstream capa's own ``ResultDocument`` schema as a
plain ``dict`` -- the same shape ``capa -j`` prints, and the same shape
``capa.render.result_document.ResultDocument.model_validate_json`` accepts
unmodified.
"""

from ._capa_x import (
    RULES_PIN,
    CapaError,
    CorruptFileError,
    InvalidRuleError,
    InvalidSignatureError,
    Rules,
    UnsupportedFormatError,
    __version__,
    analyze,
    fetch_rules,
)

__all__ = [
    "RULES_PIN",
    "CapaError",
    "CorruptFileError",
    "InvalidRuleError",
    "InvalidSignatureError",
    "Rules",
    "UnsupportedFormatError",
    "__version__",
    "analyze",
    "fetch_rules",
]
