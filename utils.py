
import wordninja


# AI couldn't find other Python code to do the country code lookup so we're using this
# ISO 3166-1 alpha-2 country codes for common TLDs
TLD_TO_COUNTRY_CODE = {
    "ac": "sh",    # Ascension Island (part of Saint Helena)
    "ae": "ae",
    "af": "af",
    "au": "au",
    "at": "at",
    "be": "be",
    "br": "br",
    "ca": "ca",
    "ch": "ch",
    "cn": "cn",
    "cz": "cz",
    "de": "de",
    "dk": "dk",
    "es": "es",
    "eu": "eu",
    "fi": "fi",
    "fr": "fr",
    "gb": "gb",  # United Kingdom (official ISO code is GB)
    "hk": "hk",
    "hu": "hu",
    "ie": "ie",
    "il": "il",
    "in": "in",
    "it": "it",
    "jp": "jp",
    "kr": "kr",
    "mx": "mx",
    "nl": "nl",
    "no": "no",
    "nz": "nz",
    "pl": "pl",
    "pt": "pt",
    "ru": "ru",
    "se": "se",
    "sg": "sg",
    "th": "th",
    "tr": "tr",
    "tw": "tw",
    "uk": "gb",  # Alias for United Kingdom
    "us": "us",
    "za": "za"
}

# Old function
def insert_space_in_compound(text: str) -> str:
    words = wordninja.split(text)

    # Fix for trailing 's' split from a name like 'danmurphys' -> ['dan', 'murphy', 's']
    if len(words) >= 2 and words[-1] == "s":
        words = words[:-2] + [words[-2] + "s"]

    return " ".join(words)

def extract_root_name_from_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-3] if parts[-2] in ["com", "org", "net", "edu", "gov"] else parts[-2]
    return domain

def retrieve_country_code(domain: str) -> str:
    """
    Returns the country code from the domain's top-level domain (TLD).
    Defaults to 'us' if not matched.
    """
    if not domain:
        print("⚠️ No domain provided.")
        return "us"

    domain = domain.lower().strip()
    #print(f"Raw domain input: '{domain}'")

    parts = domain.split(".")
    for i in range(len(parts)):
        suffix = ".".join(parts[i:])
        tld = parts[-1]
        if tld in TLD_TO_COUNTRY_CODE:
            code = TLD_TO_COUNTRY_CODE[tld]
            #print(f"✅ Matched suffix: '.{tld}' → country: '{code}'")
            return code

    print("⚠️ No matching TLD found. Using default country: 'us'")
    return "us"
