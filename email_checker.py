import re
import idna  # pip install idna (for IDN domain handling)

# Regex helpers
QUOTED_LOCAL_PART = re.compile(r'^"((?:\\.|[^"\\])*)"$')
UNQUOTED_LOCAL_CHARS = re.compile(r'^[A-Za-z0-9!#$%&\'*+/=?^_`{|}~.-]+$')
DOMAIN_LABEL = re.compile(r'^[A-Za-z0-9-]{1,63}$')
DOMAIN_LITERAL = re.compile(r'^\[(IPv6:[A-Fa-f0-9:.]+|(?:\d{1,3}\.){3}\d{1,3})\]$')

def is_valid_ipv4(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255 or str(n) != p:  # reject leading zeros
            return False
    return True

def validate_domain_literal(lit: str) -> bool:
    m = DOMAIN_LITERAL.match(lit)
    if not m:
        return False
    inside = m.group(1)
    if inside.lower().startswith("ipv6:"):
        # rough IPv6 check
        return re.match(r'^[A-Fa-f0-9:.]+$', inside[5:]) is not None
    return is_valid_ipv4(inside)

def split_email(email: str):
    """split on last @ (quoted local-part may contain @)"""
    if '@' not in email:
        return None
    local, domain = email.rsplit('@', 1)
    return local, domain

def get_email_validation_errors(email: str, allow_unicode_local=False, allow_unicode_domain=False, require_tld=True):
    errors = []
    if not isinstance(email, str):
        return ["Email must be a string"]

    email = email.strip()
    if not email:
        return ["Email is empty"]

    if len(email) > 254:
        errors.append("Email exceeds maximum length of 254 characters")

    parts = split_email(email)
    if not parts:
        return ["Missing @ symbol"]
    local, domain = parts

    # Local-part checks
    if not local:
        errors.append("Local part is empty")
    if len(local) > 64:
        errors.append("Local part exceeds 64 characters")

    quoted = QUOTED_LOCAL_PART.match(local)
    if quoted:
        inner = quoted.group(1)
        if not allow_unicode_local and re.search(r'[^\x00-\x7f]', inner):
            errors.append("Quoted local part contains non-ASCII chars")
    else:
        if not allow_unicode_local and re.search(r'[^\x00-\x7f]', local):
            errors.append("Local part contains non-ASCII chars")
        if not UNQUOTED_LOCAL_CHARS.match(local):
            errors.append("Local part contains invalid characters")
        if local.startswith('.') or local.endswith('.'):
            errors.append("Local part may not start or end with dot")
        if '..' in local:
            errors.append("Local part may not contain consecutive dots")

    # Domain checks
    if not domain:
        errors.append("Domain part is empty")
    elif len(domain) > 255:
        errors.append("Domain part exceeds 255 characters")
    elif domain.startswith('[') and domain.endswith(']'):
        if not validate_domain_literal(domain):
            errors.append("Invalid domain literal")
    else:
        # IDN handling
        try:
            domain_ascii = idna.encode(domain).decode("ascii") if allow_unicode_domain else domain
        except idna.IDNAError:
            errors.append("Invalid IDN domain")
            domain_ascii = domain

        labels = domain_ascii.split('.')
        if any(len(lbl) == 0 for lbl in labels):
            errors.append("Domain contains empty label (.. or leading/trailing dot)")
        for lbl in labels:
            if not DOMAIN_LABEL.match(lbl):
                errors.append(f"Domain label '{lbl}' is invalid")
            if lbl.startswith('-') or lbl.endswith('-'):
                errors.append(f"Domain label '{lbl}' may not start or end with hyphen")
        if require_tld and (len(labels[-1]) < 2):
            errors.append("Top-level domain must be at least 2 characters")

    return errors

def is_valid_email(email: str, **kwargs) -> bool:
    return len(get_email_validation_errors(email, **kwargs)) == 0


# ---------------- Quick tests ----------------
if __name__ == "__main__":
    valids = [
        "simple@example.com",
        "very.common@example.com",
        "user+tag@example.co.uk",
        "\"quoted@local\"@example.com",
        "user@[127.0.0.1]",
        "δοκιμή@παράδειγμα.δοκιμή",  # Greek IDN (with allow_unicode_domain=True)
    ]
    invalids = [
        "Abc.example.com",       # no @
        "john..doe@example.com", # double dot
        ".john@example.com",     # leading dot
        "john.@example.com",     # trailing dot
        "john@-example.com",     # invalid domain label
        "a" * 65 + "@example.com", # too long local
    ]
    for e in valids:
        print("VALID? ", e, "=>", is_valid_email(e, allow_unicode_domain=True))
    for e in invalids:
        print("INVALID?", e, "=>", get_email_validation_errors(e))
