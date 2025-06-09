import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify
import openai
from collections import OrderedDict
import json
from flask import Response
import threading

# AI + Scope-related functions (consolidated single import line)
from generate_scope import (
    retrieve_subdomains_only,
    retrieve_subdomain_details,
    recommend_ips_for_testing,
    retrieve_website_details,
    retrieve_mobile_app_details_for_domain,
    retrieve_mobile_app_details,
    retrieve_android_version_playwright,
    retrieve_api_details,
    retrieve_all_details
)

# Load environment variables from private.env
load_dotenv(dotenv_path="private_do_not_release/private.env")

# Set OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)


# Subdomain Discovery
@app.route("/subdomains", methods=["POST"])
def subdomains():
    """
    Flask wrapper for retrieve_subdomains().
    Uses the subfinder CLI to return a list of discovered subdomains, with a fallback to 'www.<domain>'.
    """
    data = request.json
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Missing 'domain' in request body"}), 400

    result = retrieve_subdomains_only(domain)
    if result:
        return jsonify({"subdomains": result})
    else:
        return jsonify({"error": "Failed to retrieve subdomains"})


@app.route("/subdomain-details", methods=["POST"])
def subdomain_details():
    """
    Flask wrapper for retrieve_subdomain_details().
    Uses subfinder and socket.gethostbyname to resolve subdomains,
    and enriches each with IP address, company (via IPinfo), and country.
    Returns a flat list of dictionaries with keys: subdomain, ip, company, country.
    """
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Missing domain"}), 400

    try:
        results = retrieve_subdomain_details(domain)
        return jsonify(results)
    except Exception as e:
        print(f"❌ Error in /subdomain-details: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/recommend_ip", methods=["POST"])
def recommend_ip():
    data = request.json
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Missing 'domain' in request body"}), 400

    try:
        result = recommend_ips_for_testing(domain)
        return jsonify(result)
    except Exception as e:
        print(f"❌ IP recommendation failed: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/website-details", methods=["POST"])
def website_details():
    """
    POST JSON: {
        "domain": "example.com",
        "retrieve_subdomain_details": true,
        "retrieve_ip_recommendation": true
    }

    Returns subdomain list and optional IP testing advice.
    """
    data = request.get_json()
    domain = data.get("domain", "").strip().lower()
    retrieve_subdomain_details = data.get("retrieve_subdomain_details", False)
    retrieve_ip_recommendation = data.get("retrieve_ip_recommendation", False)

    if not domain:
        return jsonify({"error": "Missing 'domain' in request"}), 400

    # Normalize booleans in case they were passed as strings
    if isinstance(retrieve_subdomain_details, str):
        retrieve_subdomain_details = retrieve_subdomain_details.strip().lower() == "true"
    if isinstance(retrieve_ip_recommendation, str):
        retrieve_ip_recommendation = retrieve_ip_recommendation.strip().lower() == "true"

    try:
        result = retrieve_website_details(
            domain,
            retrieve_subdomain_details=retrieve_subdomain_details,
            retrieve_ip_recommendation=retrieve_ip_recommendation,
            generate_subdomain_recommendation=False
        )
        return jsonify(result)
    except Exception as e:
        print(f"❌ Error in /website-details: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/website-details-testing-recommendation", methods=["POST"])
def website_details_for_testing():
    """
    POST JSON: {
        "domain": "example.com",
        "retrieve_subdomain_details": true,
        "retrieve_ip_recommendation": true
    }

    Returns subdomain list, testing recommendation, and optional IP testing advice.
    """
    data = request.get_json()
    domain = data.get("domain", "").strip().lower()
    retrieve_subdomain_details = data.get("retrieve_subdomain_details", False)
    retrieve_ip_recommendation = data.get("retrieve_ip_recommendation", False)

    if not domain:
        return jsonify({"error": "Missing 'domain' in request"}), 400

    # Normalize booleans in case they were passed as strings
    if isinstance(retrieve_subdomain_details, str):
        retrieve_subdomain_details = retrieve_subdomain_details.strip().lower() == "true"
    if isinstance(retrieve_ip_recommendation, str):
        retrieve_ip_recommendation = retrieve_ip_recommendation.strip().lower() == "true"

    try:
        result = retrieve_website_details(
            domain,
            retrieve_subdomain_details=retrieve_subdomain_details,
            retrieve_ip_recommendation=retrieve_ip_recommendation,
            generate_subdomain_recommendation=True
        )
        return jsonify(result)
    except Exception as e:
        print(f"❌ Error in /website-details-testing-recommendation: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mobile-app-details-for-domain", methods=["POST"])
def retrieve_mobile_app_details_by_domain():
    data = request.json
    domain = data.get("domain", "").strip().lower()
    search_mode = data.get("search_mode", "app_name")

    # Safely interpret retrieve_android_version as boolean
    raw_flag = data.get("retrieve_android_version", False)
    if isinstance(raw_flag, str):
        retrieve_android_version = raw_flag.strip().lower() == "true"
    else:
        retrieve_android_version = bool(raw_flag)

    if not domain:
        return Response(json.dumps({"error": "Domain is required"}), status=400, mimetype="application/json")

    raw_result = retrieve_mobile_app_details_for_domain(domain, search_mode=search_mode, retrieve_android_version=retrieve_android_version)

    # Force consistent key order
    ordered_result = OrderedDict()
    for key in ["domain", "error", "suggested_name", "bundleId", "developer", "suggested_apps", "alternatives"]:
        if key in raw_result:
            ordered_result[key] = raw_result[key]

    # Return raw JSON string to preserve order
    return Response(json.dumps(ordered_result, indent=2), mimetype="application/json")


@app.route("/mobile-app-details", methods=["POST"])
def retrieve_mobile_app_details_by_name_or_developer():
    data = request.json
    app_name = data.get("app_name", "").strip()
    developer_name = data.get("developer_name", "").strip()
    country = data.get("country", "au").lower()
    search_mode = data.get("search_mode", "app_name")

    raw_flag = data.get("retrieve_android_version", False)
    retrieve_android_version = raw_flag if isinstance(raw_flag, bool) else str(raw_flag).lower() == "true"

    if not app_name and not developer_name:
        return Response(json.dumps({"error": "Either app_name or developer_name is required"}), status=400, mimetype="application/json")

    result = retrieve_mobile_app_details(
        app_name=app_name or None,
        developer_name=developer_name or None,
        country=country,
        search_mode=search_mode,
        retrieve_android_version=retrieve_android_version
    )

    ordered = OrderedDict()
    for key in ["app_name", "developer_name", "search_mode", "error", "suggested_name", "suggested_apps", "alternatives", ]:
        if key in result:
            ordered[key] = result[key]

    return Response(json.dumps(ordered, indent=2), mimetype="application/json")


@app.route("/android-version", methods=["POST"])
def retrieve_android_version():
    """
    POST endpoint to retrieve the Android app version using Playwright.
    Request JSON must include: { "package_name": "com.example.app" }
    """
    data = request.get_json()

    if not data or "package_name" not in data:
        return jsonify({
            "error": "Missing 'package_name' in request body"
        }), 400

    package_name = data["package_name"].strip()

    if not package_name:
        return jsonify({
            "error": "Empty 'package_name' provided"
        }), 400

    version = retrieve_android_version_playwright(package_name)

    return jsonify({
        "package_name": package_name,
        "android_version": version
    })


@app.route("/api-details", methods=["POST"])
def api_details():
    data = request.json
    domain = data.get("domain")
    if not domain:
        return Response(json.dumps({"error": "Missing 'domain' parameter"}), status=400, mimetype="application/json")

    result = retrieve_api_details(domain)

    ordered = OrderedDict()
    for key in [
        "suggestedApi",
        "notes",
        "documentationUrls",
        "alternativeApis",     
        "apiUrls"
    ]:
        if key in result:
            ordered[key] = result[key]

    return Response(json.dumps(ordered, indent=2), mimetype="application/json")


@app.route("/domain-testing-information", methods=["POST"])
def domain_testing_information():
    data = request.get_json()
    domain = data.get("domain", "").strip().lower()

    if not domain:
        return jsonify({"error": "Missing 'domain' in request"}), 400

    try:
        result = retrieve_all_details(domain)
        
        # Create ordered response
        ordered = OrderedDict()
        ordered["domain"] = result["domain"]
        
        # Mobile section
        ordered["mobile"] = OrderedDict()
        ordered["mobile"]["suggested_name"] = result["mobile"].get("suggested_name")
        ordered["mobile"]["suggested_apps"] = result["mobile"].get("suggested_apps", [])
        ordered["mobile"]["alternatives"] = result["mobile"].get("alternatives", [])
        
        # API section
        ordered["api"] = OrderedDict()
        ordered["api"]["suggestedApi"] = result["api"].get("suggestedApi")
        ordered["api"]["documentationUrls"] = result["api"].get("documentationUrls", [])
        ordered["api"]["alternativeApis"] = result["api"].get("alternativeApis", [])
        ordered["api"]["notes"] = result["api"].get("notes", "")
        
        # Website section
        ordered["website"] = OrderedDict()
        ordered["website"]["subdomains"] = result["website"].get("subdomains", [])

        return Response(json.dumps(ordered, indent=2), mimetype="application/json")
    except Exception as e:
        print(f"❌ Error in /domain-insights: {e}")
        return jsonify({"error": str(e)}), 500
