import os
from typing import Any

__version__: str
RULES_PIN: str

class CapaError(Exception):
    """Base class for every exception this module raises."""

class InvalidRuleError(CapaError):
    """A rule file failed to parse, or the loaded rule set is invalid."""

class UnsupportedFormatError(CapaError):
    """The input format could not be auto-detected, or an explicit
    ``format=`` value is not one capa-x recognizes."""

class InvalidSignatureError(CapaError):
    """A FLIRT signature file failed to parse."""

class CorruptFileError(CapaError):
    """The input bytes could not be parsed or analyzed as the selected (or
    detected) format."""

class Rules:
    """An already-parsed, already-validated rule set. Build once with
    :meth:`from_directory`, reuse across any number of :func:`analyze`
    calls."""

    @staticmethod
    def from_directory(path: str | os.PathLike[str]) -> "Rules":
        """Parse every rule file under ``path`` and build the matching rule
        set. Raises :class:`InvalidRuleError` on an unparseable rule file or
        an invalid rule set (duplicate name, missing dependency, cycle)."""

def analyze(
    data_or_path: bytes | bytearray | str | os.PathLike[str],
    rules: Rules,
    *,
    jobs: int | None = None,
    format: str | None = None,
    os: str | None = None,
    arch: str | None = None,
    file_only: bool = False,
) -> dict[str, Any]:
    """Run capa-x's analysis pipeline and return upstream's
    ``ResultDocument`` schema as a ``dict``.

    :param data_or_path: raw sample bytes, or a path to read them from.
    :param rules: a :class:`Rules` instance built with
        :meth:`Rules.from_directory`.
    :param jobs: worker thread count; ``1`` is the single-threaded
        reference mode (default: available logical cores).
    :param format: ``"auto"`` (default), ``"pe"``, ``"elf"``, ``"sc32"``,
        ``"sc64"``, ``"freeze"``, ``"dotnet"``, or ``"macho"``.
    :param os: ``"auto"`` (default), ``"linux"``, ``"macos"``, or
        ``"windows"``.
    :param arch: sample architecture override (default: auto-detect).
    :param file_only: skip code recovery, extracting only file-scope
        features.
    :raises InvalidRuleError: from a bad rule set (raised by
        :meth:`Rules.from_directory`, not this function).
    :raises UnsupportedFormatError: the format could not be determined, or
        an unknown ``format=`` value was given.
    :raises InvalidSignatureError: a FLIRT signature file failed to parse.
    :raises CorruptFileError: the input could not be parsed or analyzed.
    """

def fetch_rules(directory: str | os.PathLike[str], ref: str | None = None) -> None:
    """Clone the pinned capa-rules release into ``directory``. Never runs
    implicitly -- not at import time, not as a side effect of
    :meth:`Rules.from_directory`. Requires ``git`` on ``PATH``."""
