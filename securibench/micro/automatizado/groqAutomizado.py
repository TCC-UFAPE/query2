import os
import json
import re
import time
import sys
import io
import requests 
from openpyxl import Workbook 
from groq import Groq

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

CONFIG_FILE = "config.json"

REPO_OWNER = "too4words"
REPO_NAME = "securibench-micro"
BASE_PATH = "src/securibench/micro"

EXCEL_OUTPUT_FILE = "securibench_vulnerability_analysis.xlsx"

GROQ_MODELS_TO_USE = [
    "gemma2-9b-it",
    "meta-llama/Llama-Guard-4-12B",
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "llama3-70b-8192",
    "llama3-8b-8192",
    "deepseek-r1-distill-llama-70b",
    "meta-llama/llama-4-maverick-17b-128e-instruct", 
    "meta-llama/llama-4-scout-17b-16e-instruct",  
    "mistral-saba-24b",
    "qwen-qwq-32b",
    "compound-beta",
    "compound-beta-mini",
]

PROMPT_TEMPLATE = (
    "You are a security researcher specialized in detecting security vulnerabilities.\n"
    "Provide the answer only in the following format:\n\n"
    "vulnerability: <YES or NO> | vulnerability type: <type or N/A> | vulnerability name: <name or N/A> | explanation: <explanation for the prediction>.\n"
    "Do not include anything else in the response.\n\n"
    "User: Is this code snippet subject to any security vulnerability?\n\n"
    "<CODE_SNIPPET>\n\n"
    "Answer:"
)

def load_groq_api_key(config_path): 
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
            api_key = config.get("api_key")
            if not api_key:
                print(f"Error: 'api_key' not found in {config_path}.")
                print(f"Please create {config_path} with your Groq API key, e.g., {{\"api_key\": \"YOUR_GROQ_API_KEY\"}}")
                sys.exit(1)
            return api_key
    except FileNotFoundError:
        print(f"Error: Config file {config_path} not found.")
        print(f"Please create it with your Groq API key, e.g., {{\"api_key\": \"YOUR_GROQ_API_KEY\"}}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {config_path}. Ensure it's valid JSON.")
        sys.exit(1)

def get_java_file_infos_from_github(owner, repo, base_path, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    
    api_base_url = f"https://api.github.com/repos/{owner}/{repo}/contents/"
    java_files_info = []
    
    paths_to_visit = [base_path]

    while paths_to_visit:
        current_path = paths_to_visit.pop(0)
        contents_url = f"{api_base_url}{current_path}"
        
        print(f"Fetching directory contents from: {contents_url}")
        try:
            response = requests.get(contents_url, headers=headers)
            response.raise_for_status()  
            contents = response.json()

            if not isinstance(contents, list): 
                print(f"Warning: Expected a list of items for directory '{current_path}', but got type {type(contents)}. Skipping.")
                continue

            for item in contents:
                if item["type"] == "file" and item["name"].endswith(".java"):
                    java_files_info.append((item["path"], item["download_url"]))
                elif item["type"] == "dir":
                    paths_to_visit.append(item["path"])
            
            time.sleep(0.5) 

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"Warning: Path not found on GitHub: {contents_url}. Skipping.")
            elif e.response.status_code == 403:
                print(f"Warning: GitHub API rate limit likely hit or access forbidden for {contents_url}. Try a GitHub token or wait.")
                print(f"Response: {e.response.text}")
            else:
                print(f"Error fetching contents from GitHub {contents_url}: {e}")
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching contents from GitHub {contents_url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while processing GitHub path {contents_url}: {e}")


    return java_files_info

def fetch_raw_code_from_url(download_url):
    try:
        response = requests.get(download_url)
        response.raise_for_status()
        response.encoding = 'utf-8' 
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching code from {download_url}: {e}")
        return None

def remove_java_comments(java_code):
    if not java_code:
        return ""
    code = re.sub(r"/\*.*?\*/", "", java_code, flags=re.DOTALL)
    code = re.sub(r"//.*", "", code)
    code = "\n".join(line.strip() for line in code.splitlines() if line.strip())
    return code

def analyze_code_with_groq(groq_client, model_id, code_snippet, prompt_template_with_placeholder):
    final_system_prompt_content = prompt_template_with_placeholder.replace("<CODE_SNIPPET>", code_snippet)

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": final_system_prompt_content 
                },
                {
                    "role": "user",
                    "content": code_snippet
                }
            ],
            model=model_id,
            temperature=0, 
        )
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"  Error during Groq API call for model '{model_id}': {e}")
        return f"vulnerability: ERROR | vulnerability type: API_ERROR | vulnerability name: N/A | explanation: Groq API call failed - {str(e)}"

def parse_groq_llm_response(response_text):
    parts = response_text.split(" | ")
    parsed_data = {
        "vulnerability": "PARSE_ERROR",
        "vulnerability_type": "N/A",
        "vulnerability_name": "N/A",
        "explanation": "Could not parse LLM response or response was malformed."
    }

    try:
        if len(parts) >= 1 and parts[0].lower().startswith("vulnerability:"):
            parsed_data["vulnerability"] = parts[0].split(":", 1)[1].strip()
        
        if len(parts) >= 2 and parts[1].lower().startswith("vulnerability type:"):
            parsed_data["vulnerability_type"] = parts[1].split(":", 1)[1].strip()
        
        if len(parts) >= 3 and parts[2].lower().startswith("vulnerability name:"):
            parsed_data["vulnerability_name"] = parts[2].split(":", 1)[1].strip()
        
        if len(parts) >= 4 and parts[3].lower().startswith("explanation:"):
            explanation_full = " | ".join(parts[3:]) 
            parsed_data["explanation"] = explanation_full.split(":", 1)[1].strip()
        elif parsed_data["vulnerability"] == "ERROR": 
            if "explanation:" in response_text: 
                 parsed_data["explanation"] = response_text.split("explanation:", 1)[1].strip()
                 parsed_data["explanation"] = response_text

        if parsed_data["vulnerability"] == "PARSE_ERROR" and response_text:
            parsed_data["explanation"] = f"Original unparsed response: {response_text}"

    except IndexError:
        print(f"  Warning: Could not parse all expected fields from response: '{response_text}'")
        parsed_data["explanation"] += f" (Parsing Index Error for: {response_text})"
    except Exception as e:
        print(f"  Warning: Unexpected error parsing response '{response_text}': {e}")
        parsed_data["explanation"] += f" (Unexpected Parsing Error for: {response_text} - {e})"
        
    return parsed_data

def main():
    print("Starting SecuriBench-micro vulnerability analysis script...")

    groq_api_key = load_groq_api_key(CONFIG_FILE)
    if not groq_api_key:
        return

    try:
        groq_client = Groq(api_key=groq_api_key)
        print("Groq client initialized successfully.")
    except Exception as e:
        print(f"Failed to initialize Groq client: {e}")
        return

    print(f"Fetching list of Java files from GitHub repository: {REPO_OWNER}/{REPO_NAME}, path: {BASE_PATH}...")
    java_file_infos = get_java_file_infos_from_github(REPO_OWNER, REPO_NAME, BASE_PATH, token=None)

    if not java_file_infos:
        print("No Java files found or an error occurred while fetching from GitHub. Exiting.")
        return
    print(f"Found {len(java_file_infos)} Java files to analyze.")

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Groq Vulnerability Analysis"
    excel_headers = [
        "File Path (in Repo)", "Groq Model", 
        "Vulnerability (YES/NO)", "Vulnerability Type", 
        "Vulnerability Name", "Explanation by LLM", "Raw LLM Output"
    ]
    sheet.append(excel_headers)

    total_files = len(java_file_infos)
    for i, (file_repo_path, download_url) in enumerate(java_file_infos):
        print(f"\nProcessing file {i+1}/{total_files}: {file_repo_path}")
        
        raw_java_code = fetch_raw_code_from_url(download_url)
        if raw_java_code is None:
            print(f"  Skipping file {file_repo_path} due to error fetching its content.")
            for model_id in GROQ_MODELS_TO_USE:
                error_row = [file_repo_path, model_id, "ERROR", "N/A", "N/A", "Failed to fetch file content from GitHub.", ""]
                sheet.append(error_row)
            continue

        cleaned_java_code = remove_java_comments(raw_java_code)
        if not cleaned_java_code.strip(): 
            print(f"  Skipping file {file_repo_path} as it's empty after comment removal.")
            for model_id in GROQ_MODELS_TO_USE:
                empty_row = [file_repo_path, model_id, "N/A", "N/A", "N/A", "File empty after comment removal.", ""]
                sheet.append(empty_row)
            continue

        for model_id in GROQ_MODELS_TO_USE:
            print(f"  Analyzing with Groq model: {model_id}...")
            
            llm_raw_response = analyze_code_with_groq(
                groq_client, 
                model_id, 
                cleaned_java_code, 
                PROMPT_TEMPLATE
            )
            
            parsed_llm_data = parse_groq_llm_response(llm_raw_response)
            
            excel_row_data = [
                file_repo_path,
                model_id,
                parsed_llm_data["vulnerability"],
                parsed_llm_data["vulnerability_type"],
                parsed_llm_data["vulnerability_name"],
                parsed_llm_data["explanation"],
                llm_raw_response 
            ]
            sheet.append(excel_row_data)
            
            print(f"    Model {model_id} response: Vulnerability: {parsed_llm_data['vulnerability']}")
            time.sleep(1)

    try:
        workbook.save(EXCEL_OUTPUT_FILE)
        print(f"\nAnalysis complete! Results have been saved to: {EXCEL_OUTPUT_FILE}")
    except Exception as e:
        print(f"Error saving the Excel file ({EXCEL_OUTPUT_FILE}): {e}")

if __name__ == "__main__":
    main()