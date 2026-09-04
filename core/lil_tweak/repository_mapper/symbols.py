"""Static symbol extraction for supported languages."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SymbolRecord:
    name: str
    kind: str
    line: int
    exported: bool = False
    bases: tuple[str, ...] = ()


JS_SYMBOL_RE = re.compile(
    r"""(?mx)
    ^\s*(?P<export>export\s+)?(?:
      (?P<class>class)\s+(?P<class_name>[A-Za-z_$][\w$]*)(?:\s+extends\s+(?P<extends>[A-Za-z_$][\w$.]*))?
      |(?P<function>async\s+function|function)\s+(?P<function_name>[A-Za-z_$][\w$]*)
      |(?P<const>const|let|var)\s+(?P<const_name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>
      |(?P<interface>interface)\s+(?P<interface_name>[A-Za-z_$][\w$]*)
      |(?P<type>type)\s+(?P<type_name>[A-Za-z_$][\w$]*)
    )
    """
)


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _base_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def python_symbols(source: str) -> list[SymbolRecord]:
    tree = ast.parse(source)
    records: list[SymbolRecord] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            records.append(
                SymbolRecord(
                    node.name,
                    "class",
                    node.lineno,
                    bases=tuple(filter(None, (_base_name(base) for base in node.bases))),
                )
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            records.append(
                SymbolRecord(
                    node.name,
                    "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                    node.lineno,
                )
            )
    return sorted(records, key=lambda item: (item.line, item.kind, item.name))


def js_symbols(source: str) -> list[SymbolRecord]:
    records: list[SymbolRecord] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        match = JS_SYMBOL_RE.match(line)
        if not match:
            continue
        if match.group("class"):
            records.append(
                SymbolRecord(
                    match.group("class_name"),
                    "class",
                    line_number,
                    exported=bool(match.group("export")),
                    bases=(match.group("extends"),) if match.group("extends") else (),
                )
            )
        elif match.group("function"):
            records.append(
                SymbolRecord(
                    match.group("function_name"),
                    "function",
                    line_number,
                    exported=bool(match.group("export")),
                )
            )
        elif match.group("const"):
            records.append(
                SymbolRecord(
                    match.group("const_name"),
                    "function",
                    line_number,
                    exported=bool(match.group("export")),
                )
            )
        elif match.group("interface"):
            records.append(
                SymbolRecord(
                    match.group("interface_name"),
                    "interface",
                    line_number,
                    exported=bool(match.group("export")),
                )
            )
        elif match.group("type"):
            records.append(
                SymbolRecord(
                    match.group("type_name"),
                    "type",
                    line_number,
                    exported=bool(match.group("export")),
                )
            )
    return records
