import os
import json
import re
import socket
import requests
from dotenv import load_dotenv
from collections import Counter, defaultdict
from openai import OpenAI
from playwright.sync_api import sync_playwright 
from google_play_scraper import search
from concurrent.futures import ThreadPoolExecutor
import subprocess
from collections import OrderedDict
from utils import retrieve_country_code, extract_root_name_from_domain
from typing import List, Optional
from urllib.parse import urlparse
import threading

with open("config.json", "r") as f:
    API_CONFIG = json.load(f)


def is_domain_valid(domain: str) -> bool:
    try:
        if not domain.startswith("http"):
            domain = "https://" + domain
        response = requests.get(domain, timeout=5)
        return response.status_code < 400  # consider any valid response as success
    except Exception:
        return False


def is_domain_resolvable(domain: str) -> bool:
    
    try:
        # Strip scheme and www if present
        domain = domain.replace("http://", "").replace("https://", "")
        if domain.startswith("www."):
            domain = domain[4:]
        socket.gethostbyname(domain)
        print(f"Domain resolvable: {domain}")
        return True
    except socket.gaierror:
        print(f"❌ Domain not resolvable: {domain}")
        return False


# START SUBDOMAIN CODE
def retrieve_subdomains_only(domain: str) -> list:
    """
    Retrieves subdomains using subfinder CLI. Adds fallback 'www.<domain>' even if it does not resolve.
    """
    print(f"🛠️ Running subfinder: {domain}")
    subdomains = set()

    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=True
        )
        subdomains = set(sub.strip().lower() for sub in result.stdout.strip().split("\n") if sub.strip())

    except subprocess.CalledProcessError as e:
        print(f"❌ subfinder failed for {domain}: {e}")
        subdomains = set()

    # Always add www.domain even if not resolvable
    fallback = f"www.{domain}"
    if fallback not in subdomains:
        print(f"Adding fallback: {fallback} (even if not resolvable)")
        subdomains.add(fallback)

    return sorted(subdomains)


def retrieve_subdomain_details(domain: str) -> list:
    """
    Retrieves IP, company/org, and country info for each subdomain.
    Uses IPINFO first (requires IPINFO_TOKEN in .env), and falls back to ipwho.is.

    Each result includes an 'ip_source' field indicating enrichment source: "ipinfo", "ipwho.is", or "none".
    """
    load_dotenv(dotenv_path='private_do_not_release/private.env')
    token = os.getenv("IPINFO_TOKEN")
    use_ipinfo = bool(token)

    subdomains = retrieve_subdomains_only(domain)
    results = []

    def lookup(sub):
        try:
            ip = socket.gethostbyname(sub)
        except socket.gaierror:
            return {
                "subdomain": sub,
                "ip": "Unresolved",
                "company": "Unknown",
                "country": "Unknown",
                "ip_source": "none"
            }

        company = "Unknown"
        country = "Unknown"

        # Attempt IPINFO first
        if use_ipinfo:
            try:
                url = f"https://ipinfo.io/{ip}/json?token={token}"
                response = requests.get(url, timeout=5)
                if response.ok and response.headers.get("Content-Type", "").startswith("application/json"):
                    data = response.json()
                    company = data.get("org") or data.get("asn", {}).get("name", "Unknown")
                    country = data.get("country", "Unknown")
                    return {
                        "subdomain": sub,
                        "ip": ip,
                        "company": company,
                        "country": country,
                        "ip_source": "ipinfo"
                    }
            except Exception as e:
                print(f"⚠️ IPINFO failed for {ip}: {e}")

        # Fallback to ipwho.is
        try:
            url = f"https://ipwho.is/{ip}"
            response = requests.get(url, timeout=5)
            if response.ok:
                content_type = response.headers.get("Content-Type", "")
                if "application/json" in content_type and response.text.strip().startswith("{"):
                    try:
                        data = response.json()
                        company = data.get("org") or data.get("connection", {}).get("org") or data.get("isp", "Unknown")
                        country = data.get("country", "Unknown")
                        return {
                            "subdomain": sub,
                            "ip": ip,
                            "company": company,
                            "country": country,
                            "ip_source": "ipwho.is"
                        }
                    except Exception as json_err:
                        print(f"⚠️ ipwho.is JSON parse failed for {ip}: {json_err}")
                else:
                    print(f"⚠️ ipwho.is response invalid or empty for {ip}: {response.status_code}, {content_type}")
        except Exception as e:
            print(f"⚠️ ipwho.is request failed for {ip}: {e}")

        return {
            "subdomain": sub,
            "ip": ip,
            "company": company,
            "country": country,
            "ip_source": "none"
        }

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(lookup, subdomains))

    return results


def retrieve_subdomains(domain: str, retrieve_details: bool = False) -> tuple[list, dict]:
    """
    Resolves subdomains with optional enrichment. Returns a tuple of (subdomain list, notes).
    
    Args:
        domain (str): The domain to analyze.
        retrieve_details (bool): Whether to attempt retrieve IP's and company info.
    
    Returns:
        Tuple: (list of subdomains, notes dictionary)
    """
    notes = {}
    subdomains = []

    if retrieve_details:
        try:
            subdomains = retrieve_subdomain_details(domain)
            notes["subdomain_details"] = "Subdomains retrieved and enriched with IP/company/country data."
        except Exception as e:
            print(f"⚠️ Subdomain IP and company retrieval failed: {e}")
            subdomains = retrieve_subdomains_only(domain)
            notes["subdomain_details"] = (
                "Subdomain IP and company retrieval failed or IPINFO unavailable. "
                "Falling back to basic subdomain list without IP/company/country data."
            )
    else:
        subdomains = retrieve_subdomains_only(domain)
        notes["subdomain_details"] = "Subdomains retrieved without IP/company/country data."

    return subdomains, notes

# END SUBDOMAIN CODE

# START IP CODE
def is_owned_by_org(org_text, domain_keywords):
    """
    Check if the IP ownership string includes any keyword that matches the domain.
    This is more flexible than relying on a static list of known CDN providers.
    """
    if not org_text:
        return False
    org_text = org_text.lower()
    return any(keyword.lower() in org_text for keyword in domain_keywords)


def recommend_ips_for_testing(domain: str, subdomains: list = None) -> dict:
    notes = {}

    if not subdomains:
        subdomains, retrieval_notes = retrieve_subdomains(domain, retrieve_details=True)
        notes.update(retrieval_notes)

        if not subdomains:
            return {
                "ipRecommendation": "Unavailable – no subdomains could be retrieved.",
                "mostUsedIp": None,
                "ownership": None,
                "range": None,
                "rotatingIps": [],
                "notes": notes
            }

    ip_counter = Counter()
    ip_ownership_info = {}
    subdomain_ip_map = defaultdict(list)
    unresolved_subdomains = []
    filtered_out = []

    domain_keywords = domain.replace("www.", "").replace(".com.au", "").replace(".com", "").split(".")
    domain_keywords.append(domain)

    is_detailed = isinstance(subdomains[0], dict)
    entries = subdomains

    for entry in sorted(entries, key=lambda x: x["subdomain"] if is_detailed else x):
        sub = entry["subdomain"] if is_detailed else entry
        ip = entry.get("ip") if is_detailed else None
        company = entry.get("company") if is_detailed else None

        if ip and ip != "Unresolved" and company and company != "Unknown":
            ip_ownership_info[ip] = company
            if is_owned_by_org(company, domain_keywords):
                ip_counter[ip] += 1
                subdomain_ip_map[ip].append(sub)
            else:
                filtered_out.append(sub)
            continue

        try:
            ip_results = socket.getaddrinfo(sub, None)
            resolved_ips = list({r[4][0] for r in ip_results})
            ip = next(
                (ip for ip in resolved_ips if not ip.startswith(("10.", "192.168.", "172.", "127.")) and ":" not in ip),
                None
            )
            if not ip:
                unresolved_subdomains.append(sub)
                continue
        except Exception:
            unresolved_subdomains.append(sub)
            continue

        if ip not in ip_ownership_info:
            try:
                resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
                company = resp.json().get("org", "Unknown")
                ip_ownership_info[ip] = company
            except:
                company = "Unknown"
                ip_ownership_info[ip] = company

        if is_owned_by_org(company, domain_keywords):
            ip_counter[ip] += 1
            subdomain_ip_map[ip].append(sub)
        else:
            filtered_out.append(sub)

    if not ip_counter:
        filtered_owner_counter = Counter()
        for sub in filtered_out:
            try:
                ip_results = socket.getaddrinfo(sub, None)
                for r in ip_results:
                    ip = r[4][0]
                    if ":" in ip:
                        continue
                    if ip not in ip_ownership_info:
                        try:
                            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
                            owner = resp.json().get("org", "Unknown")
                            ip_ownership_info[ip] = owner
                        except:
                            ip_ownership_info[ip] = "Unknown"
                    filtered_owner_counter[ip_ownership_info[ip]] += 1
            except:
                continue

        if not filtered_owner_counter or all(org == "Unknown" for org in ip_ownership_info.values()):
            return {
                "ipRecommendation": "Unavailable – could not resolve or enrich any IPs (e.g. API key error).",
                "mostUsedIp": None,
                "ownership": None,
                "range": None,
                "rotatingIps": [],
                "notes": notes
            }

        most_common_provider, _ = filtered_owner_counter.most_common(1)[0]
        return {
            "ipRecommendation": f"N/A Hosted by {most_common_provider}",
            "mostUsedIp": None,
            "ownership": most_common_provider,
            "range": None,
            "rotatingIps": [],
            "notes": notes
        }

    most_common_ip, count = ip_counter.most_common(1)[0]
    owner = ip_ownership_info.get(most_common_ip, "Unknown")
    asn_match = re.search(r"(AS\d+)", owner)
    asn = asn_match.group(1) if asn_match else "Unknown ASN"

    return {
        "ipRecommendation": most_common_ip,
        "mostUsedIp": most_common_ip,
        "ownership": owner,
        "range": f"{most_common_ip}/32",
        "rotatingIps": sorted(ip_counter.keys()),
        "notes": notes
    }

# END IP CODE

# START WEBSITE CODE
def is_ai_available() -> bool:
    """
    Ensures environment is loaded and checks whether the OpenAI API key is available.
    """
    load_dotenv(dotenv_path='private_do_not_release/private.env')
    return bool(os.getenv("OPENAI_API_KEY"))


def is_ipinfo_available() -> bool:
    """
    Checks if the IPinfo token is set in the environment.

    Returns:
        bool: True if IPINFO_TOKEN is present, False otherwise.
    """
    load_dotenv(dotenv_path='private_do_not_release/private.env')
    return bool(os.getenv("IPINFO_TOKEN"))


def extract_json(raw):
    # Find the first {...} block using regex
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        return json.loads(match.group(0).strip())  # ← strip any leading/trailing space
    else:
        raise json.JSONDecodeError("No JSON object found", raw, 0)


def recommend_website_subdomain_testing_ai(domain: str, subdomains: list, is_detailed: bool) -> dict:
    """
    Uses GPT to recommend which subdomains to include/exclude for testing.
    If is_detailed is True, subdomains include IP and company ownership.
    """
    try:
        load_dotenv(dotenv_path='private_do_not_release/private.env')
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    except Exception as e:
        print(f"❌ Failed to initialise OpenAI client: {e}")
        return None

    system_message = (
        "You are an expert in cybersecurity and bug bounty programs. "
        "Given a domain and a list of discovered subdomains, return a JSON object with your testing recommendations "
        "in the following format:\n\n"
        "{\n"
        '  "includeSubdomains": ["secure.example.com", "portal.example.com"],\n'
        '  "excludeSubdomains": ["test.example.com", "marketing.example.com"],\n'
        '  "aiRecommendations": "Summarise key logic behind your decisions."\n'
        "}\n\n"
        "Only include the keys shown above. Do not guess values not supported by the input. "
        "Your recommendations will be used to guide security testing scope decisions."
    )

    context_message = (
        "Each subdomain includes its IP address and the company that owns the IP. "
        "Use this information to suggest a reasonable in-scope and out-of-scope testing list. "
        "Include production systems likely to affect users or business operations. "
        "Exclude subdomains related to development (e.g. dev, uat, stage), telemetry (e.g. click, track, view), DNS/email (e.g. ns, ptr, email), or third-party infrastructure not controlled by the business."
        if is_detailed else
        "Only subdomain names are available. Recommend a reasonable testing scope based solely on this information. "
        "Include production systems likely to affect users or business operations. "
        "Exclude subdomains related to development (e.g. dev, uat, stage), telemetry (e.g. click, track, view), DNS/email (e.g. ns, ptr, email), or third-party infrastructure not controlled by the business."
    )

    messages = [
        { "role": "system", "content": system_message },
        { "role": "user", "content": f"Domain: {domain}" },
        { "role": "user", "content": context_message },
        { "role": "user", "content": f"Subdomain data:\n{json.dumps(subdomains, indent=2)}" }
    ]

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            temperature=0.2,
            response_format={ "type": "json_object" }
        )
        return extract_json(response.choices[0].message.content)
    except Exception as e:
        print(f"❌ AI recommendation failed: {e}")
        return None


def is_good_subdomain(name: str, root: str) -> bool:
    name = name.lower()
    if name == root:
        return True

    if name.endswith(f".{root}"):
        base = name[: -len(f".{root}")]
        if base.count(".") > 0:
            return False  # deeply nested, not single subdomain level

        # Rule 1: Reject 1-letter subdomains (e.g. m.bigw.com.au)
        if len(base) == 1:
            return False

        # Rule 2: Reject suspiciously long or random-looking names
        if len(base) > 20:
            vowel_ratio = len(re.findall(r"[aeiou]", base)) / len(base)
            if vowel_ratio < 0.2:  # almost no vowels → likely random
                return False

        # Rule 3: Reject common dev/test environments
        bad_fragments = ["uat", "test", "dev", "stage", "qa", "sandbox", "internal"]
        return not any(bad in base for bad in bad_fragments)

    return False


def fallback_subdomain_recommendation(subdomains: list, domain: str) -> dict:
    include_keywords = [
        "portal", "secure", "login", "dashboard", "admin",
        "app", "services", "account", "my", "client", "user", "api",
        "auth", "profile", "manage", "management", "checkout", "cart"
    ]
    exclude_keywords = [
        "test", "uat", "dev", "qa", "demo", "sandbox", "internal", "staging",
        "static", "beta", "monitor", "status"
    ]
    maybe_exclude_keywords = [
        "promo", "ads", "blog", "videos", "media", "mail", "email", "preview", "cdn", "images"
    ]

    includes = []
    excludes = []
    maybes = []
    uncertain = []

    matched_include_keywords = set()
    matched_exclude_keywords = set()
    matched_maybe_keywords = set()

    for item in subdomains:
        name = item if isinstance(item, str) else item.get("subdomain", "")
        name_lower = name.lower()

        if any(kw in name_lower for kw in exclude_keywords):
            excludes.append(name)
            matched_exclude_keywords.update([kw for kw in exclude_keywords if kw in name_lower])
            continue

        if any(kw in name_lower for kw in maybe_exclude_keywords):
            maybes.append(name)
            matched_maybe_keywords.update([kw for kw in maybe_exclude_keywords if kw in name_lower])
            continue

        if any(kw in name_lower for kw in include_keywords):
            includes.append(name)
            matched_include_keywords.update([kw for kw in include_keywords if kw in name_lower])
            continue

        if is_good_subdomain(name_lower, domain.lower()):
            includes.append(name)
            continue

        uncertain.append(name)

    explanation_lines = [
        "AI unavailable or error. Fallback recommendation based on keywords:",
        f"• MAIN WEBSITE: '{domain}' publically accessible areas should be included."
    ]

    if matched_include_keywords:
        explanation_lines.append(f"• SUGGESTED INCLUSIONS: {', '.join(sorted(matched_include_keywords))}")
    if matched_exclude_keywords:
        explanation_lines.append(f"• SUGGESTED EXCLUSIONS: {', '.join(sorted(matched_exclude_keywords))}")
    if matched_maybe_keywords:
        explanation_lines.append(
            f"• POSSIBLE EXCLUSIONS: {', '.join(sorted(matched_maybe_keywords))} (review manually)"
        )

    explanation_lines.append("NOTE: Subdomains not matching any category are marked as uncertain and may need manual review.")
    explanation_lines.append("This does not use AI.")

    explanation = "\n".join(explanation_lines)

    return {
        "includeSubdomains": sorted(includes),
        "excludeSubdomains": sorted(excludes),
        "possibleExcludeSubdomains": sorted(maybes),
        "uncertainSubdomains": sorted(uncertain),
        "aiRecommendations": explanation
    }


def retrieve_website_details(
    domain: str,
    retrieve_subdomain_details: bool = False,
    retrieve_ip_recommendation: bool = False,
    generate_subdomain_recommendation: bool = False,
    subdomains: Optional[List[str]] = None
) -> dict:
    """
    Gathers website-related data: subdomains, IP suggestions, and testing recommendations.
    Flags allow control over data enrichment and optional recommendation logic.

    Args:
        domain (str): The target domain.
        retrieve_subdomain_details (bool): Whether to retrieve subdomains with IP/org info.
        retrieve_ip_recommendation (bool): Whether to generate IP-based testing suggestions.
        generate_subdomain_recommendation (bool): Whether to produce subdomain testing advice.

    Returns:
        dict: {
            "domain": str,
            "subdomains": list,
            "subdomain_recommendation": dict or None,
            "ip_recommendation": dict or None,
            "notes": dict or None
        }
    """
    ip_recommendation = None
    subdomain_recommendation = None
    notes = {}

    if retrieve_ip_recommendation and not retrieve_subdomain_details:
        print("⚠️ IP recommendation requested without enriched subdomains. Results may be slower and less accurate.")
        notes["ip_recommendation"] = "Requested without enrichment. DNS-only resolution used (slower, less accurate)."

    # Step 1: Get subdomains with optional enrichment
    subdomains, subdomain_notes = retrieve_subdomains(domain, retrieve_details=retrieve_subdomain_details)
    notes.update(subdomain_notes)

    if not subdomains:
        print("⚠️ No subdomains found.")
        return {
            "domain": domain,
            "subdomains": [],
            "subdomain_recommendation": {
                "includeSubdomains": [],
                "excludeSubdomains": [],
                "possibleExcludeSubdomains": [],
                "uncertainSubdomains": [],
                "aiRecommendations": "No subdomains found. Cannot create recommendations."
            } if generate_subdomain_recommendation else None,
            "ip_recommendation": None,
            "notes": notes if notes else None
        }

    # Step 2: IP recommendation
    if retrieve_ip_recommendation:
        try:
            ip_recommendation = recommend_ips_for_testing(domain, subdomains)
        except Exception as e:
            print(f"⚠️ IP enrichment failed: {e}")
            ip_recommendation = {
                "ipRecommendation": "Unavailable due to error",
                "mostUsedIp": None,
                "ownership": None,
                "range": None,
                "rotatingIps": []
            }
            notes["ip_recommendation"] = "Error occurred during IP enrichment. Fallback result returned."

    # Step 3: Subdomain testing recommendation (optional)
    if generate_subdomain_recommendation:
        is_detailed = isinstance(subdomains[0], dict) if subdomains else False
        if is_ai_available():
            try:
                subdomain_recommendation = recommend_website_subdomain_testing_ai(
                    domain=domain,
                    subdomains=subdomains,
                    is_detailed=is_detailed
                )
            except Exception as e:
                print(f"⚠️ AI recommendation failed: {e}")
                subdomain_recommendation = fallback_subdomain_recommendation(subdomains, domain)
                notes["subdomain_recommendation"] = "AI failed. Fallback keyword-based logic used."
        else:
            print("⚠️ AI not available, using fallback recommendation.")
            subdomain_recommendation = fallback_subdomain_recommendation(subdomains, domain)
            notes["subdomain_recommendation"] = "AI not available. Fallback keyword-based logic used."

    return {
        "domain": domain,
        "subdomains": subdomains,
        "subdomain_recommendation": subdomain_recommendation,
        "ip_recommendation": ip_recommendation,
        "notes": notes if notes else None
    }

# END WEBSITE CODE

# START MOBILE APP CODE
def search_ios_store(search_text: str, country: str) -> list:
    """
    iOS app search that returns results in a standard schema.
    Used as a delegate with search mobile store.
    """

    try:
        url = API_CONFIG.get("ios_search_url", "https://itunes.apple.com/search")
        limit = API_CONFIG.get("mobile_app_search_limit", 5)
        timeout = API_CONFIG.get("ios_search_timeout", 10)

        response = requests.get(
            url,
            params={
                "term": search_text,
                "entity": "software",
                "limit": limit,
                "country": country
            },
            timeout=timeout
        )

        if not response.ok:
            print(f"❌ iOS API response error: {response.status_code}")
            return []

        results = response.json().get("results", [])
        #print(f"iOS Search: Raw results returned: {len(results)}")

        country = country.lower()
        standardised = []

        for app in results:
            url = app.get("trackViewUrl", "").lower()
            if f"/{country}/" not in url:
                print(f"Skipped due to country mismatch in URL: {url}")
                continue

            standardised.append({
                "name": app.get("trackName", ""),
                "id": app.get("bundleId", ""), # Keep this for deduping and to provide a consistent key for API users
                "bundle_id": app.get("bundleId", ""), # Include this for consistency with Android results
                "url": app.get("trackViewUrl", ""),
                "version": app.get("version", "Unknown"),
                "developer": app.get("sellerName", ""),
                "platform": "iOS"
            })

        return standardised

    except Exception as e:
        print(f"❗ iOS Search Error: {e}")
        return []


def search_android_store(search_text: str, country: str) -> list:
    """
    Android app search that returns results in a standard schema.
    Used as a delegate with search mobile store
    """

    try:
        results = search(search_text, lang="en", country=country.lower())
        if not results or not isinstance(results, list):
            print("Android Search: No valid results returned.")
            return []

        #print(f"Android Search: Raw results returned: {len(results)}")
        standardised = []

        base_url = API_CONFIG.get("android_play_store_base_url", "https://play.google.com/store/apps/details?id=")
        url = base_url + "{app_id}"
        limit = API_CONFIG.get("mobile_app_search_limit", 5)

        for app in results[:limit]: 
            app_id = app.get("appId")
            title = app.get("title", "")
            developer = app.get("developer", "")

            if not app_id or not title:
                continue

            standardised.append({
                "name": title,
                "id": app_id, # Keep this for deduping and to provide a consistent key for API users
                "package_name": app_id, # Include this for use of retrieving the Android version
                "url": url.replace("{app_id}", app_id),
                "version": "Unknown",
                "developer": developer,
                "platform": "Android"
            })

        return standardised

    except Exception as e:
        print(f"❗ Android Search Error: {e}")
        return []


def build_search_description(app_name, developer_name, search_mode):
    """
    Builds a human-readable search description based on mode.

    Returns:
    - str: description like "App Name = 'X'" or "App Name = 'X' AND Developer = 'Y'"
    """
    if search_mode == "app_name":
        return f"App Name = '{app_name}'"
    elif search_mode == "dev_name":
        return f"Developer = '{developer_name}'"
    elif search_mode == "both":
        return f"App Name = '{app_name}' AND Developer = '{developer_name}'"
    elif search_mode == "either":
        return f"App Name = '{app_name}' OR Developer = '{developer_name}'"
    else:
        return f"Search Mode = '{search_mode}'"


def strip_spaces_and_symbols(text: str) -> str:
    """Strips all spaces and common symbols for loose comparison."""
    return ''.join(c for c in text if c.isalnum())


def match_app(search_mode, name_match, dev_match):
    """
    Determines if an app is a match and explains the reason.

    Returns:
        (bool matched, str reason)
    """
    if search_mode == "app_name":
        if name_match:
            return True, "App name matched"
        return False, "App name did not match"

    elif search_mode == "dev_name":
        if dev_match:
            return True, "Developer name matched"
        return False, "Developer name did not match"

    elif search_mode == "either":
        if name_match or dev_match:
            reasons = []
            if name_match:
                reasons.append("App name matched")
            if dev_match:
                reasons.append("Developer name matched")
            return True, " and ".join(reasons)
        return False, "Neither app name nor developer matched"

    elif search_mode == "both":
        if name_match and dev_match:
            return True, "Both app name and developer matched"
        if name_match:
            return False, "Only app name matched (developer mismatch)"
        if dev_match:
            return False, "Only developer matched (app name mismatch)"
        return False, "Neither app name nor developer matched"

    return False, "Unknown search mode"


def search_mobile_store(app_name=None, developer_name=None, country="au", search_mode="app_name", search_func=None, platform=None) -> dict:
    """
    Generic mobile store search with flexible match modes and separated name/developer control.
    """
    if search_func is None:
        raise ValueError("A search_func must be provided.")
    if search_mode in ("app_name", "both") and not app_name:
        raise ValueError(f"search_mode='{search_mode}' requires app_name.")
    if search_mode in ("dev_name", "both") and not developer_name:
        raise ValueError(f"search_mode='{search_mode}' requires developer_name.")

    platform_label = "📱 iOS:" if platform == "iOS" else "🤖 Android:"
    search_text = app_name if search_mode in ("app_name", "both", "either") else developer_name

    stripped_app_name = strip_spaces_and_symbols(app_name or "").lower()
    stripped_dev_name = strip_spaces_and_symbols(developer_name or "").lower()

    print(f"{platform_label} Searching {search_text} with mode '{search_mode}' → {build_search_description(app_name, developer_name, search_mode)}")

    try:
        results = search_func(search_text, country)
        print(f"{platform_label} Returned {len(results)} results for query: {search_text}")
    except Exception as e:
        print(f"❌ Error while searching '{search_text}': {e}")
        return OrderedDict([
            ("app_name", app_name),
            ("developer_name", developer_name),
            ("error", str(e)),
            ("suggestions_tried", [search_text]),
            ("search_mode", search_mode),
            ("all_matches", [])
        ])

    seen = set()
    matches = []

    for app in results:
        app_id = (app.get("id") or "").strip().lower()
        app_title = (app.get("name") or "").strip()
        developer = (app.get("developer") or "").strip()

        dedupe_key = (app_id or app_title.lower(), developer.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        stripped_title = strip_spaces_and_symbols(app_title).lower()
        stripped_dev = strip_spaces_and_symbols(developer).lower()

        name_match = stripped_app_name in stripped_title if stripped_app_name else False
        dev_match = stripped_dev_name in stripped_dev if stripped_dev_name else False

        matched, reason = match_app(search_mode, name_match, dev_match)

        if matched:
            matches.append(app)
            print(f"{platform_label} ✅ Accepted: {reason} | App Name: {app_title} | Dev: {developer}")
        else:
            print(f"{platform_label} ➖ Rejected: {reason} | App Name: {app_title} | Dev: {developer}")

    if matches:
        return OrderedDict([
            ("app_name", app_name),
            ("developer_name", developer_name),
            ("suggested_app", matches[0]),
            ("alternatives", matches[1:]),
            ("all_matches", matches),
            ("search_mode", search_mode)
        ])

    return OrderedDict([
        ("app_name", app_name),
        ("developer_name", developer_name),
        ("error", "No app match found"),
        ("suggestions_tried", [search_text]),
        ("search_mode", search_mode),
        ("all_matches", [])
    ])


def retrieve_mobile_app_details(app_name=None, developer_name=None, country="au", search_mode="app_name", retrieve_android_version: bool = False) -> dict:
    if not app_name and not developer_name:
        return {"error": "Either app_name or developer_name must be provided"}

    # Decide actual search text based on mode
    search_text = app_name if search_mode != "dev_name" else developer_name

    # Run iOS and Android searches in parallel
    with ThreadPoolExecutor() as executor:
        future_ios = executor.submit(
            search_mobile_store,
            app_name=app_name,
            developer_name=developer_name,
            country=country,
            search_mode=search_mode,
            search_func=search_ios_store,
            platform="iOS"
        )
        future_android = executor.submit(
            search_mobile_store,
            app_name=app_name,
            developer_name=developer_name,
            country=country,
            search_mode=search_mode,
            search_func=search_android_store,
            platform="Android"
        )

        ios_result = future_ios.result()
        android_result = future_android.result()

    # Optionally retrieve_details Android version using Playwright
    if retrieve_android_version and android_result.get("suggested_app"):
        package_name = android_result["suggested_app"].get("package_name")
        if package_name:
            version = retrieve_android_version_playwright(package_name)
            android_result["suggested_app"]["version"] = version

    # Combine results
    suggested_apps = []
    alternatives = {}

    if ios_result.get("suggested_app"):
        suggested_apps.append(ios_result["suggested_app"])
    if ios_result.get("alternatives"):
        alternatives["iOS"] = ios_result["alternatives"]

    if android_result.get("suggested_app"):
        suggested_apps.append(android_result["suggested_app"])
    if android_result.get("alternatives"):
        alternatives["Android"] = android_result["alternatives"]

    return OrderedDict([
        ("app_name", app_name),
        ("developer_name", developer_name),
        ("search_mode", search_mode),
        ("suggested_name", suggested_apps[0]["name"] if suggested_apps else search_text),
        ("suggested_apps", suggested_apps),
        ("alternatives", alternatives)
    ])


def retrieve_mobile_app_details_for_domain(domain: str, search_mode="app_name", retrieve_android_version: bool = False) -> dict:
    """
    Returns mobile app details including platform availability and store URLs.
    Handles Android and iOS concurrently. Uses the country from domain to guide search.
    """
    if not is_domain_resolvable(domain):
        return OrderedDict([
            ("domain", domain),
            ("error", "Domain is not resolvable"),
            ("suggested_apps", []),
            ("alternatives", {}),
            ("search_mode", search_mode)
        ])

    root_name = extract_root_name_from_domain(domain).lower()
    country = retrieve_country_code(domain)
    print(f"\n🌐 Retrieve Mobile App Details For Domain: {domain} | App Name: {root_name}| Dev Name: {root_name} | Country: {country} | Search Mode: {search_mode}")

    result = retrieve_mobile_app_details(root_name, root_name, country=country, search_mode=search_mode, retrieve_android_version=retrieve_android_version)

    return OrderedDict([
        ("domain", domain),
        ("suggested_name", result["suggested_name"]),
        ("suggested_apps", result["suggested_apps"]),
        ("alternatives", result["alternatives"]),
        ("search_mode", search_mode)
    ])


def retrieve_android_version_playwright(package_name: str) -> str:
    """
    Opens the Play Store listing, triggers the modal, and extracts the Android app version using visible text only.
    """
    try:
        # print(f"🔍 Android Search: Starting Playwright scrape for: {package_name}")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Mobile Safari/537.36",
                viewport={"width": 412, "height": 915}
            )
            page = context.new_page()

            url = f"https://play.google.com/store/apps/details?id={package_name}&hl=en&gl=us"
            #print(f"Android Search: Navigating to: {url}")
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            #print("Page loaded")

            # Click the About this app button near the heading
            about_button = page.locator("//h2[text()='About this app']/ancestor::header//button")
            about_button.first.click()
            #print("Clicked 'About this app' button")

            # Wait for the modal to appear and grab its text
            modal = page.locator("div[role='dialog']")
            modal.wait_for(timeout=5000)
            #print("Modal is visible")

            modal_text = modal.inner_text()
            match = re.search(r"Version\s+([0-9.]+)", modal_text)
            if match:
                version = match.group(1)
                print(f"Android Search: Scrape Extracted Version: {version}")
                return version
            else:
                print("⚠️ Android Search: Version not found in modal text during scrape.")
                return "Unknown"

    except Exception as e:
        print(f"Android Search: Playwright scraping failed: {e}")
        return "Unknown"
    finally:
        try:
            browser.close()
            print("Android Search: Browser closed")
        except:
            pass

# END MOBILE APP CODE

# START API CODE

def retrieve_clean_base_domain(url: str) -> str:
    host = urlparse(url).hostname
    if not host:
        return url

    parts = host.split(".")
    if len(parts) <= 2:
        return host

    known_envs = {"dev", "dev1", "dev2", "dev3", "dev4", "uat", "sit", "test", "nonprod"}
    subdomain_parts = [p for p in parts[:-2] if p.lower() not in known_envs]

    # If all subdomain parts are known environments or filtered out
    if not subdomain_parts:
        return ".".join(parts[-3:])  # e.g., api.dev.example.com → api.example.com

    # Return cleaned subdomain + base domain
    clean_sub = ".".join(subdomain_parts[-2:]) if len(subdomain_parts) >= 2 else subdomain_parts[-1]
    return f"{clean_sub}.{parts[-2]}.{parts[-1]}"


def retrieve_api_details(domain: str, subdomains: Optional[List[str]] = None) -> OrderedDict:
    try:
        if subdomains is None:
            subdomains = retrieve_subdomains_only(domain)
            if not subdomains:
                return OrderedDict([
                    ("suggestedApi", None),
                    ("notes", f"No subdomains could be retrieved for {domain}."),
                    ("documentationUrls", []),
                    ("alternativeApis", []),
                    ("apiUrls", [])
                ])

        print("🔎 Scanning subdomains for API and documentation URLs...")

        all_subdomains = subdomains[:]  # keep unfiltered copy
        api_urls = set()
        doc_urls = set()

        for sub in all_subdomains:
            url = f"https://{sub}"
            lowered = sub.lower()

            if "api" in lowered:
                api_urls.add(url)

            if any(kw in lowered for kw in ["docs", "swagger", "developer", "apidocs"]):
                doc_urls.add(url)
                print(f"📝 Matched documentation keyword in: {url}")

        print(f"📦 Found {len(api_urls)} API and {len(doc_urls)} documentation subdomains.")
        print("📊 Grouping API subdomains...")

        group_map = defaultdict(list)
        for url in api_urls:
            base = retrieve_clean_base_domain(url)
            group_map[base].append(url)

        grouped_entries = []
        individual_candidates = []

        for base, urls in sorted(group_map.items(), key=lambda item: -len(item[1])):
            if len(urls) >= 3:
                grouped_entries.append(f"*.{base} (Subdomains: {len(urls)})")
            else:
                individual_candidates.extend(urls)

        def score_individual_api(url: str) -> tuple:
            host = urlparse(url).hostname or ""
            return (
                0 if host.startswith("api.") else 1,
                len(host),
                url
            )

        sorted_individuals = sorted(individual_candidates, key=score_individual_api)

        alt_results = []
        for item in grouped_entries:
            if len(alt_results) < 5:
                alt_results.append(item)

        for url in sorted_individuals:
            if len(alt_results) < 5:
                alt_results.append(url)

        default_suggested = f"https://api.{domain}"
        if default_suggested in api_urls:
            suggested_api = default_suggested
        elif alt_results:
            suggested_api = alt_results[0]
        else:
            suggested_api = None

        alt_results = [alt for alt in alt_results if alt != suggested_api]

        print("✅ API detail retrieval complete.")
        return OrderedDict([
            ("suggestedApi", suggested_api),
            ("notes", f"Found {len(api_urls)} API and {len(doc_urls)} documentation subdomains."),
            ("documentationUrls", sorted(doc_urls)),
            ("alternativeApis", alt_results),
            ("apiUrls", sorted(api_urls))
        ])
    except Exception as e:
        return OrderedDict([
            ("suggestedApi", None),
            ("notes", f"❌ Failed to process API info for {domain}: {e}"),
            ("documentationUrls", []),
            ("alternativeApis", []),
            ("apiUrls", [])
        ])

# END API CODE

# START COMBINED CODE

def retrieve_all_details(domain: str) -> OrderedDict:
    """
    Retrieves website, mobile, and API details for a given domain using threads.
    
    Returns:
        OrderedDict: {
            "domain": str,
            "mobile": {
                "suggested_name": str,
                "suggested_apps": list,
                "alternatives": list
            },
            "api": {
                "suggestedApi": str,
                "documentationUrls": list,
                "alternativeApis": list,
                "notes": str
            },
            "website": {
                "ip_recommendation": dict,
                "subdomains": list
            }
        }
    """
    results = OrderedDict()
    results["domain"] = domain
    results["mobile"] = OrderedDict()
    results["api"] = OrderedDict()
    results["website"] = OrderedDict()

    # Retrieve subdomains once
    subdomains, subdomain_notes = retrieve_subdomains(domain, retrieve_details=False)
    
    def website_thread():
        website_result = retrieve_website_details(domain, False, False, False, subdomains)
        results["website"]["subdomains"] = website_result.get("subdomains", [])

    def mobile_thread():
        mobile_result = retrieve_mobile_app_details_for_domain(domain)
        results["mobile"]["suggested_name"] = mobile_result.get("suggested_name")
        results["mobile"]["suggested_apps"] = mobile_result.get("suggested_apps", [])
        results["mobile"]["alternatives"] = mobile_result.get("alternatives", {}) 

    def api_thread():
        api_result = retrieve_api_details(domain, subdomains)
        results["api"]["suggestedApi"] = api_result.get("suggestedApi")
        results["api"]["documentationUrls"] = api_result.get("documentationUrls", [])
        results["api"]["alternativeApis"] = api_result.get("alternativeApis", [])
        results["api"]["notes"] = api_result.get("notes", "")

    threads = [
        threading.Thread(target=website_thread),
        threading.Thread(target=mobile_thread),
        threading.Thread(target=api_thread)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return results


