# Nylas API Key Generator

A command-line utility for generating authenticated requests to the Nylas Admin API for API key management.

## Overview

This script provides a secure way to interact with the Nylas Admin API for creating and deleting API keys. It handles all the necessary authentication steps including:

- Generating secure nonces
- Creating canonical JSON representations
- Signing requests with RSA private keys
- Formatting proper authentication headers
- Generating ready-to-use cURL commands

## Prerequisites

- Python 3.6+
- Required Python packages:
  - cryptography
  - python-dotenv

## Installation

1. Clone this repository or download the script
2. Install required dependencies: 
   ```
   pip install cryptography python-dotenv
   ```
3. Create a `.env` file based on the provided `.env.example`:
   ```
   cp .env.example .env
   ```
4. Edit the `.env` file and add your Nylas credentials:
   - `NYLAS_PRIVATE_KEY_BASE64`: Your Base64-encoded private key
   - `NYLAS_PRIVATE_KEY_ID`: Your private key ID
   - `NYLAS_APP_ID`: Your application ID
   - `NYLAS_API_URL`: https://api.us.nylas.com/v3

## Usage

The script can be used to create or delete API keys:

### Create a new API key

```bash
python nylas_api_key_generator.py create --name "my-api-key" --expires 3600
```

### Delete an existing API key

```bash
python nylas_api_key_generator.py delete <api_key_id>
```

### Debug mode

Add the `--debug` flag to any command to see detailed information about the signing process:

```bash
python nylas_api_key_generator.py create --debug
```