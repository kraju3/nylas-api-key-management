#!/usr/bin/env python3
"""
Nylas API Key Utility

A utility tool for managing Nylas API keys programmatically.
This script can be imported and used in automation systems for key rotation.
"""

import base64
import json
import time
import secrets
import string
import hashlib
import argparse
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

# Get constants from environment variables
PRIVATE_KEY_BASE64 = os.environ.get("NYLAS_PRIVATE_KEY_BASE64")
PRIVATE_KEY_ID = os.environ.get("NYLAS_PRIVATE_KEY_ID")
APP_ID = os.environ.get("NYLAS_APP_ID")
NYLAS_API_URL = os.environ.get("NYLAS_API_URL")
BASE_PATH = f"/v3/admin/applications/{APP_ID}/api-keys"


def generate_nonce():
    """Generate a 20-character secure nonce."""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(20))


def canonical_json(data):
    """
    Produce a minified JSON string with keys sorted alphabetically.
    This ensures consistency in the string representation for signing.
    """
    return json.dumps(data, separators=(',', ':'), sort_keys=True)


def load_private_key():
    """Load the RSA private key from the Base64-encoded PEM."""
    try:
        private_key_pem = base64.b64decode(PRIVATE_KEY_BASE64)
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
        )
        return private_key
    except Exception as e:
        raise Exception(f"Error loading private key: {e}")


def generate_signature(path, method, payload=None, debug=False):
    """
    Generate a signature for the Nylas Admin API request.

    Args:
        path: API endpoint path
        method: HTTP method (GET, POST, DELETE, etc.)
        payload: Optional JSON payload for POST/PUT requests
        debug: Whether to print debug information

    Returns:
        dict: Headers and request information needed for the API call
    """
    private_key = load_private_key()
    if not private_key:
        return None

    # Generate timestamp & nonce
    timestamp = int(time.time())
    nonce = generate_nonce()

    # Create canonical data
    canonical_data = {
        "path": path,
        "method": method.lower(),
        "timestamp": timestamp,
        "nonce": nonce
    }

    # Add payload for POST/PUT requests
    payload_json = None
    if payload and method.lower() in ["post", "put"]:
        payload_json = canonical_json(payload)
        canonical_data["payload"] = payload_json

    # Create canonical JSON string
    canonical_json_str = canonical_json(canonical_data)

    if debug:
        print("Canonical JSON Before Signing:", canonical_json_str)

    # Hash the canonical JSON string using SHA-256
    hashed = hashlib.sha256(canonical_json_str.encode('utf-8')).digest()

    if debug:
        print("Signing Hash:", hashed.hex())

    # Sign the hash using RSA with PKCS1v15
    try:
        signature = private_key.sign(
            hashed,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )
    except Exception as e:
        raise Exception(f"Error signing data: {e}")

    # Encode the signature in Base64
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    # Create result with headers and request information
    result = {
        "headers": {
            "X-Nylas-Signature": signature_b64,
            "X-Nylas-Nonce": nonce,
            "X-Nylas-Timestamp": str(timestamp),
            "X-Nylas-Kid": PRIVATE_KEY_ID
        },
        "request_info": {
            "path": path,
            "method": method,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature_b64
        }
    }

    if payload_json:
        result["request_info"]["payload"] = payload_json

    return result


def create_api_key(name, expires_in=100, debug=False):
    """Generate signature for creating a new API key."""
    payload = {
        "name": name,
        "expires_in": expires_in
    }
    if debug:
        print(f"Creating API key with name: {name}, expires_in: {expires_in}")
    return generate_signature(BASE_PATH, "post", payload, debug)


def delete_api_key(api_key_id, debug=False):
    """Generate signature for deleting an API key."""
    path = f"{BASE_PATH}/{api_key_id}"
    if debug:
        print(f"Deleting API key with ID: {api_key_id}")
    return generate_signature(path, "delete", debug=debug)


def get_api_key(api_key_id, debug=False):
    """Generate signature for retrieving an API key by ID."""
    path = f"{BASE_PATH}/{api_key_id}"
    if debug:
        print(f"Getting API key with ID: {api_key_id}")
    return generate_signature(path, "get", debug=debug)


def list_api_keys(debug=False):
    """Generate signature for retrieving API Keys."""
    if debug:
        print("Listing all API keys")
    return generate_signature(BASE_PATH, "get", debug=debug)


def make_http_request(result, debug=False):
    """Make an HTTP request using the requests library."""
    headers = result["headers"]
    req_info = result["request_info"]

    method = req_info["method"].lower()
    path = req_info["path"]

    # Base URL
    base_url = NYLAS_API_URL
    full_url = f"{base_url}{path}"

    if debug:
        print(f"Making {method.upper()} request to: {full_url}")
        print(f"Headers: {json.dumps(headers, indent=2)}")

    # Add content-type for POST/PUT
    if method in ["post", "put"] and "payload" in req_info:
        headers["Content-Type"] = "application/json"
        payload = json.loads(req_info["payload"])

        # Make the request
        response = requests.request(
            method=method,
            url=full_url,
            headers=headers,
            json=payload
        )
    else:
        # For GET, DELETE, etc.
        response = requests.request(
            method=method,
            url=full_url,
            headers=headers
        )

    if debug:
        print(f"Response status code: {response.status_code}")
        try:
            print(f"Response body: {json.dumps(response.json(), indent=2)}")
        except:
            print(f"Response body: {response.text}")

    return response


def check_environment():
    """Check if all required environment variables are set."""
    missing = []
    if not PRIVATE_KEY_BASE64:
        missing.append("NYLAS_PRIVATE_KEY_BASE64")
    if not PRIVATE_KEY_ID:
        missing.append("NYLAS_PRIVATE_KEY_ID")
    if not APP_ID:
        missing.append("NYLAS_APP_ID")
    if not NYLAS_API_URL:
        missing.append("NYLAS_API_URL")

    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")


# API Functions for programmatic use

def create_key(name, expires_in=7776000, debug=False):
    """
    Create a new API key.

    Args:
        name (str): Name for the API key
        expires_in (int): Expiration time in seconds (default: 90 days)
        debug (bool): Whether to print debug information

    Returns:
        dict: API key details including id and secret
    """
    check_environment()
    result = create_api_key(name, expires_in, debug)
    response = make_http_request(result, debug)

    if response.status_code >= 400:
        raise Exception(f"Error creating API key: {response.status_code} - {response.text}")

    return response.json()


def get_key(api_key_id, debug=False):
    """
    Get details for an API key.

    Args:
        api_key_id (str): ID of the API key to retrieve
        debug (bool): Whether to print debug information

    Returns:
        dict: API key details
    """
    check_environment()
    result = get_api_key(api_key_id, debug)
    response = make_http_request(result, debug)

    if response.status_code >= 400:
        raise Exception(f"Error retrieving API key: {response.status_code} - {response.text}")

    return response.json()


def list_keys(debug=False):
    """
    List all API keys.

    Args:
        debug (bool): Whether to print debug information

    Returns:
        list: List of API keys
    """
    check_environment()
    result = list_api_keys(debug)
    response = make_http_request(result, debug)

    if response.status_code >= 400:
        raise Exception(f"Error listing API keys: {response.status_code} - {response.text}")

    return response.json()


def delete_key(api_key_id, debug=False):
    """
    Delete an API key.

    Args:
        api_key_id (str): ID of the API key to delete
        debug (bool): Whether to print debug information

    Returns:
        bool: True if deletion was successful
    """
    check_environment()
    result = delete_api_key(api_key_id, debug)
    response = make_http_request(result, debug)

    if response.status_code >= 400:
        raise Exception(f"Error deleting API key: {response.status_code} - {response.text}")

    return True


def rotate_key(old_key_id, new_key_name, expires_in=7776000, debug=False):
    """
    Rotate an API key by creating a new one and optionally deleting the old one.

    Args:
        old_key_id (str): ID of the old API key to replace
        new_key_name (str): Name for the new API key
        expires_in (int): Expiration time in seconds for the new key
        debug (bool): Whether to print debug information

    Returns:
        dict: New API key details
    """
    # Create new key
    new_key = create_key(new_key_name, expires_in, debug)

    if debug:
        print(f"Created new API key: {new_key['id']}")
        print("You should update your applications to use the new key before deleting the old one")

    return {
        "old_key_id": old_key_id,
        "new_key": new_key,
        "message": "Update your applications with the new key before deleting the old one"
    }


def complete_rotation(old_key_id, debug=False):
    """
    Complete a key rotation by deleting the old key.

    Args:
        old_key_id (str): ID of the old API key to delete
        debug (bool): Whether to print debug information

    Returns:
        bool: True if deletion was successful
    """
    return delete_key(old_key_id, debug)


def main():
    """Command-line interface for the utility."""
    parser = argparse.ArgumentParser(description="Nylas API Key Utility")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create API key command
    create_parser = subparsers.add_parser("create", help="Create a new API key")
    create_parser.add_argument("--name", default="api-key", help="Name for the API key")
    create_parser.add_argument("--expires", type=int, default=7776000,
                               help="Expiration time in seconds (default: 90 days)")
    create_parser.add_argument("--debug", action="store_true", help="Print debug information")

    # Get API key command
    get_parser = subparsers.add_parser("get", help="Get an API key by ID")
    get_parser.add_argument("api_key_id", help="ID of the API key to retrieve")
    get_parser.add_argument("--debug", action="store_true", help="Print debug information")

    # List API keys command
    list_parser = subparsers.add_parser("list", help="List all API keys")
    list_parser.add_argument("--debug", action="store_true", help="Print debug information")

    # Delete API key command
    delete_parser = subparsers.add_parser("delete", help="Delete an API key")
    delete_parser.add_argument("api_key_id", help="ID of the API key to delete")
    delete_parser.add_argument("--debug", action="store_true", help="Print debug information")

    # Rotate API key command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate an API key (create new, keep old)")
    rotate_parser.add_argument("old_key_id", help="ID of the old API key to replace")
    rotate_parser.add_argument("--name", default=f"rotated-key-{int(time.time())}", help="Name for the new API key")
    rotate_parser.add_argument("--expires", type=int, default=7776000,
                               help="Expiration time in seconds (default: 90 days)")
    rotate_parser.add_argument("--debug", action="store_true", help="Print debug information")

    # Complete rotation command
    complete_parser = subparsers.add_parser("complete-rotation", help="Complete rotation by deleting the old key")
    complete_parser.add_argument("old_key_id", help="ID of the old API key to delete")
    complete_parser.add_argument("--debug", action="store_true", help="Print debug information")

    args = parser.parse_args()

    try:
        check_environment()

        if args.command == "create":
            result = create_key(args.name, args.expires, args.debug)
            if not args.debug:
                print(json.dumps(result, indent=2))

        elif args.command == "get":
            result = get_key(args.api_key_id, args.debug)
            if not args.debug:
                print(json.dumps(result, indent=2))

        elif args.command == "list":
            result = list_keys(args.debug)
            if not args.debug:
                print(json.dumps(result, indent=2))

        elif args.command == "delete":
            result = delete_key(args.api_key_id, args.debug)
            if not args.debug:
                print(json.dumps({"success": result, "message": f"API key {args.api_key_id} deleted successfully"},
                                 indent=2))

        elif args.command == "rotate":
            result = rotate_key(args.old_key_id, args.name, args.expires, args.debug)
            if not args.debug:
                print(json.dumps(result, indent=2))

        elif args.command == "complete-rotation":
            result = complete_rotation(args.old_key_id, args.debug)
            if not args.debug:
                print(json.dumps(
                    {"success": result, "message": f"Rotation completed. Old key {args.old_key_id} deleted."},
                    indent=2))

        else:
            parser.print_help()
            sys.exit(1)

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main() 