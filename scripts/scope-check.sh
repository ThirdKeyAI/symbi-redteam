#!/usr/bin/env bash
# =============================================================================
# scope-check.sh -- Defense-in-depth scope validation for tool wrappers
#
# Sourced by all tool wrappers to validate targets against the engagement
# scope BEFORE execution. This is a secondary check -- Cedar policies are
# the primary enforcement mechanism at the ORGA Gate. This script catches
# cases where a bug in the runtime or policy engine allows an out-of-scope
# target to reach the wrapper.
#
# Usage: source /app/scripts/scope-check.sh
#        validate_scope "$TARGET"         # IPv4/CIDR only -- exits 2 if out of scope
#        validate_domain_scope "$DOMAIN"  # domain only -- exits 2 if out of scope
# =============================================================================

# Allowed CIDR prefixes (must match scope.toml and scope.cedar)
ALLOWED_PREFIXES=(
    "10.0.1."      # Staging subnet A
    "10.0.2."      # Staging subnet B
    "192.168.10."  # Lab network
    "10.10.0."     # DMZ (recon only)
    "172.17.0.2"   # Docker test target
)

# Explicitly excluded targets
EXCLUDED_TARGETS=(
    "10.0.0.1"     # Core router
    "10.0.0.2"     # DNS server
)

EXCLUDED_PREFIXES=(
    "10.0.100."    # Finance VLAN
    "10.100."      # Production DB
)

# Allowed domains for tools that require hostnames (e.g., amass subdomain enum)
ALLOWED_DOMAINS=(
    "acme-staging.local"
    "acme-dev.local"
    "acme-lab.local"
)

# Strict IPv4 dotted-quad regex (each octet 0-255)
IPV4_OCTET='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
IPV4_RE="^${IPV4_OCTET}\.${IPV4_OCTET}\.${IPV4_OCTET}\.${IPV4_OCTET}$"
CIDR_RE="^${IPV4_OCTET}\.${IPV4_OCTET}\.${IPV4_OCTET}\.${IPV4_OCTET}/([0-9]|[12][0-9]|3[0-2])$"

validate_scope() {
    local target="$1"

    # Strip CIDR notation for IP comparison
    local ip="${target%%/*}"

    # -----------------------------------------------------------------------
    # STRICT IP FORMAT VALIDATION
    # Only accept valid IPv4 addresses. Reject hostnames, qualified names,
    # and anything else that could resolve to an out-of-scope IP at runtime
    # (prevents hostname-prefix bypass and DNS rebinding TOCTOU attacks).
    # -----------------------------------------------------------------------
    if [[ ! "$target" =~ $IPV4_RE ]] && [[ ! "$target" =~ $CIDR_RE ]]; then
        echo "ERROR: Target must be a valid IPv4 address or CIDR -- hostnames are not allowed: ${target}" >&2
        echo "HINT: Resolve hostnames to IPs via dns_enumerate before scanning" >&2
        exit 2
    fi

    # Check excluded targets first (deny overrides allow)
    for excluded in "${EXCLUDED_TARGETS[@]}"; do
        if [[ "$ip" == "$excluded" ]]; then
            echo "ERROR: Target $target is explicitly excluded from scope" >&2
            exit 2
        fi
    done

    for prefix in "${EXCLUDED_PREFIXES[@]}"; do
        if [[ "$ip" == "$prefix"* ]]; then
            echo "ERROR: Target $target is in excluded range ${prefix}*" >&2
            exit 2
        fi
    done

    # Block external targets (not RFC 1918)
    if [[ ! "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
        echo "ERROR: Target $target is external (not RFC 1918) -- out of scope" >&2
        exit 2
    fi

    # Block unowned RFC 1918 ranges
    if [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        # Only 172.17.0.2 is allowed in the 172.16-31.x range
        if [[ "$ip" != "172.17.0.2" ]]; then
            echo "ERROR: Target $target is in unowned RFC 1918 range -- out of scope" >&2
            exit 2
        fi
    fi

    # Check against allowed prefixes
    local in_scope=false
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        if [[ "$ip" == "$prefix"* ]]; then
            in_scope=true
            break
        fi
    done

    if [[ "$in_scope" != "true" ]]; then
        echo "ERROR: Target $target is not in any allowed scope range" >&2
        exit 2
    fi
}

# Validate a domain name against the allowed domains list.
# Used by tools that require hostnames (amass, etc.) instead of IPs.
validate_domain_scope() {
    local domain="$1"

    # Must look like a domain (letters, digits, hyphens, dots only)
    if ! [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "ERROR: Invalid domain format: ${domain}" >&2
        exit 2
    fi

    # Must contain at least one dot
    if ! [[ "$domain" =~ \. ]]; then
        echo "ERROR: Target must be a fully qualified domain name: ${domain}" >&2
        exit 2
    fi

    # Check against allowed domains (exact match or subdomain of allowed)
    local in_scope=false
    for allowed in "${ALLOWED_DOMAINS[@]}"; do
        if [[ "$domain" == "$allowed" ]] || [[ "$domain" == *".${allowed}" ]]; then
            in_scope=true
            break
        fi
    done

    if [[ "$in_scope" != "true" ]]; then
        echo "ERROR: Domain $domain is not in any allowed scope domain" >&2
        exit 2
    fi
}
