"""
Breach Simulation Pipeline with Active Validation (Chunk-Safe)
- Fetch scripts from a target URL
- Decompress / decode common formats
- Send clean text to an LLM for secret extraction (safe-chunked with overlap)
- Merge results from multiple scripts
- Actively validate against Azure Cosmos DB and Blob Storage (if authorized)
- Explain secrets in human-readable Markdown (also chunk-safe)
"""

# ==============================
# IMPORTS
# ==============================
import os                                   # For accessing environment variables like API keys
import json                                 # For working with JSON data
import gzip, brotli, zlib, base64           # For handling compressed or encoded formats
import zipfile, io                          # For working with in-memory ZIP archives
import requests                              # For making HTTP(S) requests to fetch pages/scripts
from bs4 import BeautifulSoup               # For parsing HTML to find <script> tags
from urllib.parse import urljoin            # For building absolute URLs from relative ones
from dotenv import load_dotenv              # For loading .env variables into environment
from openai import OpenAI                    # Cerebras/OpenAI-compatible client for the LLM

# Local helper modules for Azure validation (you provide these implementations)
from access_cosmos import access_cosmos      # Custom function to validate Cosmos DB creds
from access_blob import access_blob          # Custom function to validate Blob Storage creds

# ==============================
# ENVIRONMENT + CLIENT SETUP
# ==============================
load_dotenv()                                # Load environment variables from .env
CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY")  # Retrieve API key from env vars

if not CEREBRAS_API_KEY:                     # If API key is missing
    raise RuntimeError("CEREBRAS_API_KEY not set")

# Create an API client for the Cerebras LLM
cerebras_client = OpenAI(
    api_key=CEREBRAS_API_KEY,                 # Pass API key
    base_url="https://api.cerebras.ai/v1"     # Cerebras endpoint
)

# ==============================
# CONSTANTS
# ==============================
REQUEST_TIMEOUT = 10                          # HTTP GET timeout in seconds
CHUNK_MAX = 100_000                           # Max characters allowed per chunk
CHUNK_OVERLAP = 1_000                         # Overlap between chunks to avoid cutting secrets

# Centralized prompts so you can edit them easily
SECRET_EXTRACTION_PROMPT = """
You are a cloud security analyst. 
Extract any hardcoded secrets, API keys, or connection strings from the provided JavaScript.
Return ONLY valid JSON in this format:
{ "SECRET_TYPE": ["value1", "value2"] }
Do not add commentary.
"""

SECRET_EXPLANATION_PROMPT = """
You are a cloud security analyst.

For each key and its values in this JSON:
{json_chunk}

Explain in a Markdown table with the columns:
- Secret Key
- Likely Meaning
- What It Reveals
- Sensitivity (Low / Medium / High)
- Risk (1–10)

Do not add commentary outside the table.
"""

# ==============================
# CHUNKING UTILITY
# ==============================
def chunk_if_large(text, max_size=CHUNK_MAX, overlap=CHUNK_OVERLAP):
    """
    Break a long string into overlapping segments so secrets split over boundaries aren't lost.
    """
    if not isinstance(text, str):             # Ensure input is string
        text = str(text)
    if len(text) <= max_size:                  # If small enough, no chunking needed
        return [text]
    chunks = []                                # Where we'll store chunks
    start = 0                                  # Start position
    while start < len(text):                   # Keep making chunks until we reach end
        end = min(start + max_size, len(text)) # End index for this chunk
        chunks.append(text[start:end])         # Add chunk to list
        start += max_size - overlap            # Advance with overlap
    return chunks                              # Return all chunks

# ==============================
# DETECT + EXTRACT FUNCTION
# ==============================
def detect_and_extract(raw_bytes, filename=None):
    """
    Try to detect compression/encoding type and return decoded UTF-8 text.
    Returns tuple: (status, text or None)
    """
    if filename:                               
        lower_name = filename.lower()
        if lower_name.endswith(".gz"):         # Check for gzip by extension
            try: return ("decompressed", gzip.decompress(raw_bytes).decode("utf-8", "replace"))
            except Exception: pass
        if lower_name.endswith(".br"):         # Check for Brotli
            try: return ("decompressed", brotli.decompress(raw_bytes).decode("utf-8", "replace"))
            except Exception: pass
        if lower_name.endswith(".zip"):        # Check for Zip archives
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                    contents = []
                    for name in zf.namelist():  # Loop files in archive
                        try:
                            contents.append(zf.read(name).decode("utf-8", "replace"))
                        except Exception:
                            pass
                    if contents:                # If we found any readable content
                        return ("decompressed", "\n".join(contents))
            except Exception: pass
    # Check magic bytes for gzip
    if raw_bytes.startswith(b"\x1f\x8b"):
        try: return ("decompressed", gzip.decompress(raw_bytes).decode("utf-8", "replace"))
        except Exception: pass
    # Try other compression formats
    try: return ("decompressed", brotli.decompress(raw_bytes).decode("utf-8", "replace"))
    except Exception: pass
    try: return ("decompressed", zlib.decompress(raw_bytes).decode("utf-8", "replace"))
    except Exception: pass
    # Try base64 decode
    try:
        b64_decoded = base64.b64decode(raw_bytes, validate=True)
        if b64_decoded:
            try: return ("deserialized", b64_decoded.decode("utf-8"))
            except Exception: pass
    except Exception: pass
    # Try JSON decode
    try:
        json_obj = json.loads(raw_bytes.decode("utf-8"))
        return ("deserialized", json.dumps(json_obj, indent=2))
    except Exception: pass
    # Try plain UTF-8 text
    try: return ("text", raw_bytes.decode("utf-8"))
    except Exception: pass
    return ("binary", None)                    # Unknown/binary

# ==============================
# SCRIPT FETCHER
# ==============================
def fetch_scripts_from_url(target_url):
    """
    Fetch HTML and extract inline and external JavaScript content.
    """
    resp = requests.get(target_url, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    scripts_content = []

    for script_tag in soup.find_all("script"):
        src = script_tag.get("src")
        if src:
            script_url = src if src.startswith(("http://", "https://")) else urljoin(target_url, src)
            try:
                js_resp = requests.get(script_url, timeout=REQUEST_TIMEOUT)
                js_resp.raise_for_status()
                status, decoded = detect_and_extract(js_resp.content, filename=src)
                if status in ("decompressed", "deserialized", "text") and decoded:
                    scripts_content.append(decoded)
                    print(f"[INFO] Fetched {status} script: {script_url}")
                else:
                    print(f"[SKIP] {script_url} classified as {status}")
            except Exception as e:
                print(f"[WARN] Could not fetch {script_url}: {e}")
        else:
            inline_code = script_tag.string or ""
            if inline_code.strip():
                scripts_content.append(inline_code)
                print("[INFO] Fetched inline script.")

    return scripts_content

# ==============================
# STRIP CODE FENCES
# ==============================
def _extract_json_text(text):
    """
    Remove Markdown-style code fences from a string, if present.
    """
    if text.startswith("```"):
        try:
            first_newline = text.find("\n")
            body = text[first_newline + 1 :]
            end_idx = body.rfind("```")
            if end_idx != -1:
                return body[:end_idx].strip()
        except Exception:
            pass
    return text

# ==============================
# LLM ANALYSIS (CHUNK-SAFE + ROBUST)
# ==============================
def analyze_with_llm(script_block):
    """
    Send JavaScript code to the LLM for JSON-only secret extraction, with safety guards.
    """
    all_results = {}
    chunks = chunk_if_large(script_block)

    for i, chunk in enumerate(chunks, 1):
        # Build prompt with central extraction instructions + code chunk
        user_prompt = SECRET_EXTRACTION_PROMPT + "\nSource code:\n" + chunk

        try:
            response = cerebras_client.chat.completions.create(
                model="gpt-oss-120b",
                messages=[
                    {"role": "system", "content": "You are a helpful and precise cloud security analyst."},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0
            )

            # Get raw output and strip whitespace
            raw = response.choices[0].message.content.strip()   # Get the model's output text and remove leading/trailing whitespace

            # SAFETY CHECK 1 — If output is completely empty, skip this chunk
            if not raw:
                print(f"[WARN] Chunk {i} returned no output.")  # Warn that this chunk produced nothing
                continue                                        # Go to next chunk without parsing

            # Clean the output by removing any surrounding Markdown code fences
            raw = _extract_json_text(raw)

            # 🛡 SAFETY CHECK 2 — If cleaning removed everything, skip this chunk
            if not raw:
                print(f"[WARN] Chunk {i} returned no JSON after stripping fences.")
                continue

            # Try to parse the JSON text into a Python object
            try:
                chunk_results = json.loads(raw)
            except json.JSONDecodeError as e:
                # If the JSON is invalid, log the error and skip this chunk
                print(f"[WARN] Chunk {i} JSON decode failed: {e}")
                continue

            # Loop through each key in the parsed JSON results
            for key, values in chunk_results.items():
                if not isinstance(values, list):                # Ensure values is always a list
                    values = [values]
                if key not in all_results:                      # Create a new list if key not present
                    all_results[key] = []
                for v in values:
                    if v not in all_results[key]:                # Avoid duplicates
                        all_results[key].append(v)

        except Exception as e:
            # This catches errors like API call failures
            print(f"[ERROR] LLM call failed on chunk {i}: {e}")

    return all_results                                          # Return the merged results from all chunks

# ==============================
# PIPELINE ORCHESTRATOR
# ==============================
def run_pipeline(target_url):
    """
    Coordinates the full process:
    1. Fetch JS scripts from a target URL
    2. Analyze each one for secrets
    3. Merge results from all scripts
    4. Try active validation against Azure resources if possible
    """
    scripts = fetch_scripts_from_url(target_url)      # Get all inline & external JS code blocks
    all_secrets = {}                                  # Master dictionary for ALL secrets found

    # Loop through each JavaScript snippet
    for idx, snippet in enumerate(scripts, start=1):  
        print(f"\n[INFO] Analyzing script #{idx}...")
        secrets = analyze_with_llm(snippet)           # Run chunk‑safe LLM extraction on this snippet

        if not secrets:                               # If no secrets were found at all
            print(f"[SKIP] Script #{idx}: no secrets found.")
            continue                                  # Move to the next script

        # Merge this snippet's secrets into the master dictionary
        for key, values in secrets.items():
            if key not in all_secrets:                # If this type of secret is new
                all_secrets[key] = []                 # Create a list to hold its values
            for val in values:                        
                if val not in all_secrets[key]:       # Only add unique values (no duplicates)
                    all_secrets[key].append(val)

    # Show the collected results
    print("\n=== ALL SECRETS FOUND ===")
    if not all_secrets:                               # No secrets found at all
        print("(none)")
    else:
        for key, values in all_secrets.items():       
            for val in values:
                print(f'{key} = "{val}"')             # Print in KEY = "value" format

    # Try Cosmos DB access only if both URL and KEY were found
    if "COSMOS_URL" in all_secrets and "COSMOS_KEY" in all_secrets:
        for url, key in zip(all_secrets["COSMOS_URL"], all_secrets["COSMOS_KEY"]):
            print(f"\n[INFO] Attempting Cosmos DB access: {url}")
            try:
                access_cosmos(url, key)               # Validate credentials against Cosmos DB
            except Exception as e:
                print(f"[ERROR] Cosmos DB access failed: {e}")

    # Try Blob Storage access if connection strings were found
    if "BLOB_CONNECTION_STRING" in all_secrets:
        for conn_str in all_secrets["BLOB_CONNECTION_STRING"]:
            print(f"\n[INFO] Attempting Blob Storage access...")
            try:
                access_blob(conn_str)                 # Validate credentials against Blob Storage
            except Exception as e:
                print(f"[ERROR] Blob Storage access failed: {e}")

    return all_secrets                                # Return the combined results


# ==============================
# EXPLAIN SECRETS FUNCTION
# ==============================
def explain_secrets(secrets_dict):
    """
    Uses the LLM to create a human-readable Markdown table explaining each secret found.
    Handles large input by chunking JSON.
    """
    json_text = json.dumps(secrets_dict, indent=2)    # Convert secrets dict to nicely formatted JSON string
    chunks = chunk_if_large(json_text)                # Split into chunks if too long for one call
    partial_tables = []                               # Holds each chunk's table output

    # Analyze each chunk separately
    for i, chunk in enumerate(chunks, 1):
        user_prompt = SECRET_EXPLANATION_PROMPT.format(json_chunk=chunk)  # Fill template with chunk
        try:
            resp = cerebras_client.chat.completions.create(
                model="gpt-oss-120b",                  # LLM model
                messages=[
                    {"role": "system", "content": "You are a helpful and precise cloud security analyst."},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0                          # Deterministic output
            )
            partial_tables.append(resp.choices[0].message.content.strip())  # Save table text
        except Exception as e:
            print(f"[ERROR] LLM explanation failed on chunk {i}: {e}")

    # If more than one table, combine them into a single complete table
    if len(partial_tables) > 1:
        combine_prompt = (
            "Combine these partial Markdown tables into one complete table, "
            "no rows lost, no extra commentary:\n\n" +
            "\n\n---\n\n".join(partial_tables)
        )
        try:
            resp = cerebras_client.chat.completions.create(
                model="gpt-oss-120b",
                messages=[
                    {"role": "system", "content": "You are a helpful and precise cloud security analyst."},
                    {"role": "user", "content": combine_prompt}
                ],
                temperature=0
            )
            return resp.choices[0].message.content.strip()    # Return the final merged table
        except Exception as e:
            print(f"[ERROR] Table combine failed: {e}")
            return "\n\n---\n\n".join(partial_tables)         # Fallback: join with separators
    else:
        return partial_tables[0] if partial_tables else ""    # Return single table or empty string


# ==============================
# ENTRY POINT
# ==============================
if __name__ == "__main__":
    target = input("Enter target URL: ").strip()              # Ask the user for the target website
    if not target:                                            # If nothing was entered
        print("[ERROR] No URL provided. Exiting.")            # Error message and quit
    else:
        results = run_pipeline(target)                        # Run the full pipeline
        if results:                                           # If secrets were found
            try:
                with open("secrets_found.json", "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)           # Save them to a JSON file
                print("[INFO] Secrets saved to secrets_found.json")
            except Exception as e:
                print(f"[ERROR] Could not save secrets: {e}")

            print("\n=== SECRETS ANALYSIS ===")
            table = explain_secrets(results)                  # Get the explanation table from the LLM
            print(table)                                      # Display it
        else:
            print("[INFO] No secrets found.")                 # Inform if nothing was found
