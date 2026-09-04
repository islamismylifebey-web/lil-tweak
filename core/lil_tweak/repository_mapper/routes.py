"""Conservative static API-route discovery."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .contracts import SourceLocation


@dataclass(frozen=True, slots=True)
class DiscoveredRoute:
    method: str
    route_path: str
    defining_symbol: str
    location: SourceLocation
    framework: str


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def discover_python_routes(tree: ast.AST, module_name: str) -> tuple[DiscoveredRoute, ...]:
    routes: list[DiscoveredRoute] = []
    if not isinstance(tree, ast.Module):
        return ()
    methods = {"get", "post", "put", "patch", "delete", "options", "head", "route", "api_route"}
    for statement in tree.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in statement.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            called = decorator.func.attr.lower()
            if called not in methods or not decorator.args:
                continue
            path = _literal_string(decorator.args[0])
            if path is None:
                continue
            discovered_methods: tuple[str, ...]
            if called in {"route", "api_route"}:
                values: list[str] = []
                for keyword in decorator.keywords:
                    if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                        values.extend(
                            str(element.value).upper()
                            for element in keyword.value.elts
                            if isinstance(element, ast.Constant) and isinstance(element.value, str)
                        )
                discovered_methods = tuple(sorted(set(values))) or ("UNKNOWN",)
            else:
                discovered_methods = (called.upper(),)
            location = SourceLocation(
                start_line=max(1, int(getattr(decorator, "lineno", statement.lineno))),
                start_column=max(0, int(getattr(decorator, "col_offset", 0))),
                end_line=getattr(decorator, "end_lineno", None),
                end_column=getattr(decorator, "end_col_offset", None),
            )
            defining = f"{module_name}.{statement.name}" if module_name else statement.name
            for method in discovered_methods:
                routes.append(DiscoveredRoute(method, path, defining, location, "python-decorator"))
    return tuple(routes)


_HTTP_EXPORT = re.compile(
    r"(?m)^\s*export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\("
)
_EXPRESS_ROUTE = re.compile(
    r"(?m)\b(?:app|router)\.(get|post|put|patch|delete|options|head)\s*\(\s*([\"'])([^\"']+)\2"
)


def _next_route_path(path: str) -> str | None:
    parts = list(PurePosixPath(path).parts)
    try:
        app_index = max(index for index, part in enumerate(parts) if part in {"app", "pages"})
    except ValueError:
        return None
    if app_index + 1 >= len(parts) or parts[app_index + 1] != "api":
        return None
    name = parts[-1].lower()
    if not (name.startswith("route.") or (parts[app_index] == "pages" and name.split(".")[0])):
        return None
    route_parts = parts[app_index + 1 : -1]
    normalized: list[str] = []
    for part in route_parts:
        if part.startswith("(") and part.endswith(")"):
            continue
        if part.startswith("[") and part.endswith("]"):
            inner = part[1:-1].lstrip(".")
            normalized.append("{" + inner + "}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)


def _location(content: str, start: int, end: int) -> SourceLocation:
    line = content.count("\n", 0, start) + 1
    column = start - (content.rfind("\n", 0, start) + 1)
    end_line = content.count("\n", 0, end) + 1
    end_column = end - (content.rfind("\n", 0, end) + 1)
    return SourceLocation(line, column, end_line, end_column)


def discover_javascript_routes(content: str, path: str, module_name: str) -> tuple[DiscoveredRoute, ...]:
    routes: list[DiscoveredRoute] = []
    next_path = _next_route_path(path)
    if next_path is not None:
        for match in _HTTP_EXPORT.finditer(content):
            method = match.group(1)
            routes.append(
                DiscoveredRoute(
                    method,
                    next_path,
                    f"{module_name}.{method}" if module_name else method,
                    _location(content, match.start(), match.end()),
                    "next-route",
                )
            )
    for match in _EXPRESS_ROUTE.finditer(content):
        method = match.group(1).upper()
        route_path = match.group(3)
        routes.append(
            DiscoveredRoute(
                method,
                route_path,
                module_name,
                _location(content, match.start(), match.end()),
                "express-like",
            )
        )
    unique = {(item.method, item.route_path, item.location.start_line): item for item in routes}
    return tuple(unique[key] for key in sorted(unique))
