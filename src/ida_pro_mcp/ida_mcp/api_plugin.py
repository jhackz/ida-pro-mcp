"""IDA Plugin Integrations - Access data from third-party IDA plugins

Currently supported:
- Flare Capa: Capability detection results stored in IDB netnodes
"""

import json
from typing import Annotated

import ida_netnode

from .rpc import tool
from .sync import idasync, IDAError
from .utils import (
    Page,
    normalize_list_input,
    paginate,
    pattern_filter,
    parse_address,
    get_function,
)

# ============================================================================
# Capa Integration
# ============================================================================

CAPA_NETNODE_PREFIX = "$ com.mandiant.capa.v"
CAPA_NETNODE_RESULTS_KEY = "results"

# Session cache for capa data
_capa_cache: dict = {}


def _find_capa_netnode() -> tuple[str | None, str | None]:
    """Find capa netnode by scanning for matching name pattern.

    Returns:
        (netnode_name, version) or (None, None) if not found
    """
    node = ida_netnode.netnode()

    # Start iteration from the first netnode
    if not node.start():
        return None, None

    while True:
        name = node.get_name()
        if name and name.startswith(CAPA_NETNODE_PREFIX):
            version = name[len(CAPA_NETNODE_PREFIX) :]
            return name, version

        if not node.next():
            break

    return None, None


def _get_capa_data() -> tuple[dict | None, str | None, str | None]:
    """Get cached capa results, loading from netnode if needed.

    Returns:
        (results_dict, version, error_message)
    """
    global _capa_cache

    if "data" in _capa_cache:
        return _capa_cache["data"], _capa_cache.get("version"), None

    # Check for netnode library (third-party, handles JSON/compression)
    try:
        from netnode import netnode
    except ImportError:
        return None, None, "netnode library not installed (required for Capa integration)"

    # Find capa netnode by scanning
    nodename, version = _find_capa_netnode()
    if not nodename:
        return None, None, "No capa results found in IDB"

    # Load results from netnode using third-party library
    try:
        n = netnode.Netnode(nodename)
        json_str = n.get(CAPA_NETNODE_RESULTS_KEY)
        if not json_str:
            return None, None, "Capa netnode exists but contains no results"

        data = json.loads(json_str)
        _capa_cache["data"] = data
        _capa_cache["version"] = version
        return data, version, None

    except json.JSONDecodeError as e:
        return None, None, f"Failed to parse capa results: {e}"
    except Exception as e:
        return None, None, f"Failed to load capa results: {e}"


def _clear_capa_cache():
    """Clear the session cache (call if IDB changes)."""
    global _capa_cache
    _capa_cache = {}


def _extract_scope(meta: dict) -> str:
    """Extract scope string from rule metadata."""
    scopes = meta.get("scopes", {})
    if isinstance(scopes, dict):
        return scopes.get("static") or scopes.get("dynamic") or "unknown"
    return str(scopes) if scopes else "unknown"


def _extract_match_addresses(matches: list) -> list[str]:
    """Extract addresses from match list."""
    addresses = []
    for match in matches:
        if not isinstance(match, (list, tuple)) or len(match) < 1:
            continue
        addr_info = match[0]
        if isinstance(addr_info, dict):
            if addr_info.get("type") == "absolute":
                value = addr_info.get("value")
                if value is not None:
                    addresses.append(hex(value))
        elif isinstance(addr_info, int):
            addresses.append(hex(addr_info))
    return addresses


@tool
@idasync
def capa_status() -> dict:
    """Check if capa results exist in the IDB and get analysis metadata"""
    data, version, error = _get_capa_data()

    if error:
        return {"available": False, "error": error}

    meta = data.get("meta", {})
    rules = data.get("rules", {})

    sample = meta.get("sample", {})
    analysis = meta.get("analysis", {})

    return {
        "available": True,
        "version": version,
        "metadata": {
            "sample_md5": sample.get("md5"),
            "sample_sha256": sample.get("sha256"),
            "sample_sha1": sample.get("sha1"),
            "sample_path": sample.get("path"),
            "timestamp": meta.get("timestamp"),
            "analysis_format": analysis.get("format"),
            "analysis_arch": analysis.get("arch"),
            "analysis_os": analysis.get("os"),
            "analysis_extractor": analysis.get("extractor"),
        },
        "summary": {
            "total_rules_matched": len(rules),
        },
    }


@tool
@idasync
def capa_rules(
    filter: Annotated[str, "Glob pattern to filter rule names (optional)"] = "",
    scope: Annotated[
        str, "Filter by scope: function, file, basic block, or * for all"
    ] = "*",
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Number of results (0=all, max 500)"] = 50,
) -> Page[dict]:
    """List matched capa rules with filtering and pagination"""
    data, version, error = _get_capa_data()

    if error:
        raise IDAError(error)

    rules = data.get("rules", {})

    # Build rule summaries
    summaries = []
    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})
        matches = rule_data.get("matches", [])

        # Extract scope
        rule_scope = _extract_scope(meta)

        # Filter by scope
        if scope != "*" and rule_scope != scope:
            continue

        # Extract ATT&CK and MBC mappings
        attack = meta.get("attack", [])
        mbc = meta.get("mbc", [])

        # Collect match addresses
        addresses = _extract_match_addresses(matches)

        summaries.append(
            {
                "name": rule_name,
                "namespace": meta.get("namespace"),
                "scope": rule_scope,
                "description": meta.get("description"),
                "attack": attack,
                "mbc": mbc,
                "match_count": len(matches),
                "addresses": addresses[:10],  # Limit preview
                "has_more_addresses": len(addresses) > 10,
            }
        )

    # Apply name filter
    if filter:
        summaries = pattern_filter(summaries, filter, "name")

    # Sort by name
    summaries.sort(key=lambda r: r["name"])

    # Enforce count limit
    if count <= 0 or count > 500:
        count = 500

    return paginate(summaries, offset, count)


@tool
@idasync
def capa_rule(
    names: Annotated[list[str] | str, "Rule name(s) to get details for"],
) -> list[dict]:
    """Get detailed information about specific capa rules including full match data"""
    names = normalize_list_input(names)
    data, version, error = _get_capa_data()

    if error:
        raise IDAError(error)

    rules = data.get("rules", {})
    results = []

    for name in names:
        if name in rules:
            rule_data = rules[name]
            meta = rule_data.get("meta", {})

            results.append(
                {
                    "name": name,
                    "namespace": meta.get("namespace"),
                    "authors": meta.get("authors", []),
                    "scope": _extract_scope(meta),
                    "description": meta.get("description"),
                    "references": meta.get("references", []),
                    "attack": meta.get("attack", []),
                    "mbc": meta.get("mbc", []),
                    "matches": rule_data.get("matches", []),
                    "source": rule_data.get("source"),
                    "error": None,
                }
            )
        else:
            results.append(
                {
                    "name": name,
                    "error": f"Rule not found: {name}",
                }
            )

    return results


@tool
@idasync
def capa_at(
    addrs: Annotated[list[str] | str, "Addresses to check for capa matches"],
) -> list[dict]:
    """Get all capa capabilities detected at specific addresses or within their functions"""
    addrs = normalize_list_input(addrs)
    data, version, error = _get_capa_data()

    if error:
        raise IDAError(error)

    rules = data.get("rules", {})
    results = []

    for addr_str in addrs:
        try:
            target_addr = parse_address(addr_str)

            # Get function containing address (if any)
            func = get_function(target_addr, raise_error=False)
            func_start = parse_address(func["addr"]) if func else None

            matched_rules = []

            for rule_name, rule_data in rules.items():
                meta = rule_data.get("meta", {})
                matches = rule_data.get("matches", [])

                for match in matches:
                    if not isinstance(match, (list, tuple)) or len(match) < 1:
                        continue

                    addr_info = match[0]
                    match_value = None

                    if isinstance(addr_info, dict):
                        if addr_info.get("type") == "absolute":
                            match_value = addr_info.get("value")
                    elif isinstance(addr_info, int):
                        match_value = addr_info

                    if match_value is None:
                        continue

                    # Check exact match or function scope
                    is_match = match_value == target_addr
                    if not is_match and func_start is not None:
                        is_match = match_value == func_start

                    if is_match:
                        matched_rules.append(
                            {
                                "rule": rule_name,
                                "namespace": meta.get("namespace"),
                                "scope": _extract_scope(meta),
                                "description": meta.get("description"),
                                "attack": meta.get("attack", []),
                                "mbc": meta.get("mbc", []),
                                "match_addr": hex(match_value),
                            }
                        )
                        break  # Only add rule once per address query

            results.append(
                {
                    "addr": addr_str,
                    "function": func,
                    "capabilities": matched_rules,
                    "count": len(matched_rules),
                    "error": None,
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "capabilities": [],
                    "count": 0,
                    "error": str(e),
                }
            )

    return results
