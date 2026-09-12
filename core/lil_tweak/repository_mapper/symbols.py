"""Static symbol extraction for supported repository languages."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .contracts import NodeKind, SourceLocation


@dataclass(frozen=True, slots=True)
class DiscoveredSymbol:
    name: str
    qualified_name: str
    kind: NodeKind
    symbol_type: str
    location: SourceLocation
    exported: bool
    bases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveredCall:
    caller_qualified_name: str
    callee_name: str
    location: SourceLocation


def _location(node: ast.AST) -> SourceLocation:
    return SourceLocation(
        start_line=max(1, int(getattr(node, "lineno", 1))),
        start_column=max(0, int(getattr(node, "col_offset", 0))),
        end_line=getattr(node, "end_lineno", None),
        end_column=getattr(node, "end_col_offset", None),
    )


def _expression_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _expression_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _expression_name(node.value)
    return ""


def _python_contract(name: str, bases: tuple[str, ...]) -> bool:
    suffix = name.lower()
    if suffix.endswith(("model", "schema", "contract", "protocol", "interface")):
        return True
    base_names = {base.rsplit(".", 1)[-1].lower() for base in bases}
    return bool(base_names & {"basemodel", "protocol", "typeddict", "abc"})


def discover_python_symbols(tree: ast.AST, module_name: str) -> tuple[tuple[DiscoveredSymbol, ...], tuple[DiscoveredCall, ...]]:
    symbols: list[DiscoveredSymbol] = []
    calls: list[DiscoveredCall] = []
    exported_names: set[str] | None = None
    if isinstance(tree, ast.Module):
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        value = statement.value
                        if isinstance(value, (ast.List, ast.Tuple)):
                            exported_names = {
                                element.value
                                for element in value.elts
                                if isinstance(element, ast.Constant) and isinstance(element.value, str)
                            }

    def is_exported(name: str) -> bool:
        return name in exported_names if exported_names is not None else not name.startswith("_")

    if not isinstance(tree, ast.Module):
        return (), ()

    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = f"{module_name}.{statement.name}" if module_name else statement.name
            symbols.append(
                DiscoveredSymbol(
                    statement.name,
                    qualified,
                    NodeKind.SYMBOL,
                    "function",
                    _location(statement),
                    is_exported(statement.name),
                )
            )
            for node in ast.walk(statement):
                if isinstance(node, ast.Call):
                    name = _expression_name(node.func)
                    if name:
                        calls.append(DiscoveredCall(qualified, name, _location(node)))
        elif isinstance(statement, ast.ClassDef):
            bases = tuple(filter(None, (_expression_name(base) for base in statement.bases)))
            qualified = f"{module_name}.{statement.name}" if module_name else statement.name
            kind = NodeKind.CONTRACT if _python_contract(statement.name, bases) else NodeKind.SYMBOL
            symbol_type = "contract" if kind == NodeKind.CONTRACT else "class"
            symbols.append(
                DiscoveredSymbol(
                    statement.name,
                    qualified,
                    kind,
                    symbol_type,
                    _location(statement),
                    is_exported(statement.name),
                    bases,
                )
            )
            for member in statement.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_qualified = f"{qualified}.{member.name}"
                    symbols.append(
                        DiscoveredSymbol(
                            member.name,
                            method_qualified,
                            NodeKind.SYMBOL,
                            "method",
                            _location(member),
                            not member.name.startswith("_"),
                        )
                    )
                    for node in ast.walk(member):
                        if isinstance(node, ast.Call):
                            name = _expression_name(node.func)
                            if name:
                                calls.append(DiscoveredCall(method_qualified, name, _location(node)))
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id.isupper() and target.id != "__all__":
                    qualified = f"{module_name}.{target.id}" if module_name else target.id
                    symbols.append(
                        DiscoveredSymbol(
                            target.id,
                            qualified,
                            NodeKind.SYMBOL,
                            "constant",
                            _location(statement),
                            is_exported(target.id),
                        )
                    )
    return tuple(symbols), tuple(calls)


_JS_EXPORT = re.compile(
    r"(?m)^\s*export\s+(?:declare\s+)?(?:async\s+)?(?P<kind>interface|type|class|function|const|let|var|enum)\s+(?P<name>[A-Za-z_$][\w$]*)"
)
_JS_METHOD = re.compile(r"(?m)^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*(?P<name>[A-Za-z_$][\w$]*)\s*\(")
_JS_CALL = re.compile(r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")


def _line_location(content: str, offset: int, end_offset: int | None = None) -> SourceLocation:
    line = content.count("\n", 0, offset) + 1
    column = offset - (content.rfind("\n", 0, offset) + 1)
    if end_offset is None:
        return SourceLocation(line, column)
    end_line = content.count("\n", 0, end_offset) + 1
    end_column = end_offset - (content.rfind("\n", 0, end_offset) + 1)
    return SourceLocation(line, column, end_line, end_column)


def discover_javascript_symbols(content: str, module_name: str) -> tuple[tuple[DiscoveredSymbol, ...], tuple[DiscoveredCall, ...]]:
    symbols: list[DiscoveredSymbol] = []
    calls: list[DiscoveredCall] = []
    for match in _JS_EXPORT.finditer(content):
        symbol_kind = match.group("kind")
        name = match.group("name")
        qualified = f"{module_name}.{name}" if module_name else name
        contract = symbol_kind in {"interface", "type"} or name.lower().endswith(("schema", "contract", "model", "interface"))
        node_kind = NodeKind.CONTRACT if contract else NodeKind.SYMBOL
        symbols.append(
            DiscoveredSymbol(
                name,
                qualified,
                node_kind,
                "contract" if contract else symbol_kind,
                _line_location(content, match.start(), match.end()),
                True,
            )
        )
    # Calls are intentionally conservative: only named invocations are retained;
    # resolution to known symbols happens after the complete graph is available.
    for match in _JS_CALL.finditer(content):
        callee = match.group("name")
        if callee in {"if", "for", "while", "switch", "catch", "function"}:
            continue
        calls.append(DiscoveredCall(module_name, callee, _line_location(content, match.start(), match.end())))
    return tuple(symbols), tuple(calls)
