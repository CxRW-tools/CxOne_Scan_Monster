import sys
import json
import requests  # version 2.31.0
import datetime
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import urlparse

# Global variables
base_url = None
tenant_name = None
auth_url = None
iam_base_url = None
auth_token = None
debug = False

def generate_auth_url():
    global iam_base_url
        
    try:
        if debug:
            print("Generating authentication URL...")
        
        if iam_base_url is None:
            iam_base_url = base_url.replace("ast.checkmarx.net", "iam.checkmarx.net")
            if debug:
                print(f"Generated IAM base URL: {iam_base_url}")
        
        temp_auth_url = f"{iam_base_url}/auth/realms/{tenant_name}/protocol/openid-connect/token"
        
        if debug:
            print(f"Generated authentication URL: {temp_auth_url}")
        
        return temp_auth_url
    except AttributeError:
        print("Error: Invalid base_url provided.")
        sys.exit(1)

def authenticate(api_key):
    if auth_url is None:
        return None
    
    if debug:
        print("Authenticating with API...")
        
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {api_key}'
    }
    data = {
        'grant_type': 'refresh_token',
        'client_id': 'ast-app',
        'refresh_token': api_key
    }
    
    try:
        response = requests.post(auth_url, headers=headers, data=data)
        response.raise_for_status()
        
        json_response = response.json()
        access_token = json_response.get('access_token')
        
        if not access_token:
            print("Error: Access token not found in the response.")
            return None
        
        if debug:
            print("Successfully authenticated.")
        
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during authentication: {e}")
        sys.exit(1)

def read_repo_urls(file_path):
    try:
        if debug:
            print(f"Reading repository URLs from file: {file_path}")
        with open(file_path, 'r') as file:
            repo_urls = [line.strip() for line in file]
        if debug:
            print(f"Read {len(repo_urls)} repository URLs from file.")
        return repo_urls
    except Exception as e:
        print(f"An error occurred while reading the repository URLs: {e}")
        sys.exit(1)

def get_repo_info(repo_url, github_token=None, gitlab_token=None, bitbucket_token=None, azure_token=None):
    try:
        parsed_url = urlparse(repo_url)
        project_repo_info = {}
        headers = {}

        # GitHub
        if 'github.com' in parsed_url.netloc:
            project_repo_info['platform'] = 'GitHub'
            if github_token:
                headers['Authorization'] = f'token {github_token}'
            api_url = f'https://api.github.com/repos{parsed_url.path}'

        # GitLab
        elif 'gitlab.com' in parsed_url.netloc:
            project_repo_info['platform'] = 'GitLab'
            if gitlab_token:
                headers['Authorization'] = f'Bearer {gitlab_token}'
            api_url = f'https://gitlab.com/api/v4/projects{parsed_url.path.replace("/", "%2F")}'

        # Bitbucket
        elif 'bitbucket.org' in parsed_url.netloc:
            project_repo_info['platform'] = 'Bitbucket'
            if bitbucket_token:
                headers['Authorization'] = f'Bearer {bitbucket_token}'
            api_url = f'https://api.bitbucket.org/2.0/repositories{parsed_url.path}'

        # Azure DevOps
        elif 'dev.azure.com' in parsed_url.netloc:
            project_repo_info['platform'] = 'AzureDevOps'
            if azure_token:
                headers['Authorization'] = f'Bearer {azure_token}'
            project_repo = parsed_url.path.strip('/').split('/')
            api_url = f'https://dev.azure.com/{project_repo[0]}/{project_repo[2]}/_apis/git/repositories/{project_repo[2]}?api-version=7.0'

        else:
            raise ValueError(f'Unsupported platform for repository URL: {repo_url}')

        # Fetch primary branch
        if debug:
            print(f'Fetching primary branch from: {api_url}')

        response = requests.get(api_url, headers=headers)
        
        # Check for a successful response
        if response.status_code not in (200, 203):
            print(f'Error: Received status code {response.status_code} from {api_url}')
            print(f'Response text: {response.text}')
            sys.exit(1)
        
        response.raise_for_status()  # This will also check for error status codes, but it's good to have a custom message above
        repo_info = response.json()

        # Determine projectName
        if project_repo_info['platform'] == 'GitHub' or project_repo_info['platform'] == 'GitLab':
            project_repo_info['projectName'] = f"{project_repo_info['platform']}-{repo_info.get('full_name')}"
        elif project_repo_info['platform'] == 'Bitbucket':
            project_repo_info['projectName'] = f"{project_repo_info['platform']}-{repo_info.get('full_name')}"
        elif project_repo_info['platform'] == 'AzureDevOps':
            project_repo_info['projectName'] = f"{project_repo_info['platform']}-{repo_info.get('project', {}).get('name')}-{repo_info.get('name')}"

        if project_repo_info['platform'] == 'GitHub' or project_repo_info['platform'] == 'GitLab':
            project_repo_info['primary_branch'] = repo_info.get('default_branch')
        elif project_repo_info['platform'] == 'Bitbucket':
            project_repo_info['primary_branch'] = repo_info.get('mainbranch', {}).get('name')
        elif project_repo_info['platform'] == 'AzureDevOps':
            project_repo_info['primary_branch'] = repo_info.get('defaultBranch')

        if debug:
            print(f'Project and repo information: {project_repo_info}')

        return project_repo_info

    except requests.exceptions.RequestException as e:
        print(f'An error occurred while fetching the repository info: {e}')
        sys.exit(1)

    except Exception as e:
        print(f'An unexpected error occurred: {e}')
        sys.exit(1)

def check_project_exists(project_name):
    if debug:
        print(f"Checking if project exists: {project_name}")
    
    headers = {
        'Accept': 'application/json; version=1.0',
        'Authorization': f'Bearer {auth_token}',
    }
    
    params = {
        "name": project_name
    }

    projects_url = f"{base_url}/api/projects/"

    try:
        response = requests.get(projects_url, headers=headers, params=params)
        response.raise_for_status()
        projects = response.json()
        
        for project in projects['projects']:
            if project.get('name') == project_name:
                if debug:
                    print(f"Project found: {project_name}")
                return project.get('id')
        
        if debug:
            print(f"No project found for: {project_name}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking for project existence: {e}")
        sys.exit(1)

def create_project(project_name, repo_url, main_branch):
    headers = {
        'Accept': 'application/json; version=1.0',
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json; version=1.0',
        'CorrelationId': ''
    }
    data = {
        "name": project_name,
        "groups": [],
        "repoUrl": repo_url,
        "mainBranch": main_branch,
        "origin": "ScanMonster",
        "tags": {
            "ScanMonster": ""
        },
        "criticality": 3
    }
    
    data = {key: list(value) if isinstance(value, set) else value for key, value in data.items()}
    
    projects_url = f"{base_url}/api/projects/"
    
    try:
        response = requests.post(projects_url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while creating the project: {e}")
        if response.content:
            print(f"Response content: {response.content}")
        sys.exit(1)
    
    project_id = response.json().get('id')
    if not project_id:
        print("Error: Project ID not found in the response.")
        return None
    
    if debug:
        print(f"Project {project_name} created successfully with project ID: {project_id}.")
    
    return project_id

def start_scan(repo_info, repo_url):
    # Build the headers for the request
    headers = {
        'Accept': 'application/json; version=1.0',
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json; version=1.0',
        'CorrelationId': ''
    }
    
    # Extract the branch name from 'refs/heads/' if present
    if 'refs/heads/' in repo_info['primary_branch']:
        repo_info['primary_branch'] = repo_info['primary_branch'].split('refs/heads/')[-1]
    
    # Build the handler object for the request payload
    handler = {
        "repoUrl": repo_url,
        "branch": repo_info['primary_branch'],
        "tags": {
            "ScanMonster Scan": ""
            }
    }
    
    # Build the project object for the request payload
    project = {
        "id": repo_info['projectId'],
        "tags": {}
    }
 
    # Build the config object for the request payload
    config = [
        {
            "type": "sast",
            "value": {
                "incremental": "false",
                "presetName": "Top Tier",
                "engineVerbose": "false"
            }
        },
        {
            "type": "kics",
            "value": {
            }
        },
        {
            "type": "sca",
            "value": {
            }
        }
    ]
 
    # Build the request payload
    payload = {
        "type": "git",
        "handler": handler,
        "project": project,
        "config": config,
        "tags": {
            "ScanMonster Scan": ""
            },
        "branch": repo_info['primary_branch']
    }
      
    # Send the request to the Checkmarx API
    scans_url = f"{base_url}/api/scans/"
    try:
        response = requests.post(scans_url, headers=headers, json=payload)
        response.raise_for_status()  # Check for HTTP errors
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while starting the scan: {e}")
        if response.content:
            print(f"Response content: {response.content}")
        sys.exit(1)
    
    print(f"Started scan for {repo_info['projectName']}")

def main():
    global base_url
    global tenant_name
    global debug
    global auth_url
    global auth_token
    global iam_base_url

    parser = argparse.ArgumentParser(description='Initiate scans on a set of repositories using Checkmarx One APIs')
    parser.add_argument('--base_url', required=True, help='Region Base URL')
    parser.add_argument('--iam_base_url', required=False, help='Region IAM Base URL')
    parser.add_argument('--tenant_name', required=True, help='Tenant name')
    parser.add_argument('--api_key', required=True, help='API key for authentication')
    parser.add_argument('--repo_file', required=True, help='File containing list of repository URLs')
    parser.add_argument('--github_token', required=False, help='GitHub personal access token')
    parser.add_argument('--gitlab_token', required=False, help='GitLab personal access token')
    parser.add_argument('--bitbucket_token', required=False, help='Bitbucket personal access token')
    parser.add_argument('--azure_token', required=False, help='Azure DevOps personal access token')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    base_url = args.base_url
    tenant_name = args.tenant_name
    github_token = args.github_token
    gitlab_token = args.gitlab_token
    bitbucket_token = args.bitbucket_token
    azure_token = args.azure_token
    debug = args.debug
    
    # Set iam_base_url if it's provided as an argument
    if args.iam_base_url:
        iam_base_url = args.iam_base_url
    
    auth_url = generate_auth_url()
    auth_token = authenticate(args.api_key)
    
    if auth_token is None:
        return

    repo_urls = read_repo_urls(args.repo_file)
    
    for repo_url in repo_urls:
        repo_info = get_repo_info(repo_url, github_token, gitlab_token, bitbucket_token, azure_token)
        repo_info['projectId'] = check_project_exists(repo_info['projectName'])
        
        if repo_info['projectId'] is None:
            repo_info['projectId'] = create_project(repo_info['projectName'], repo_url, repo_info['primary_branch'])
        
        start_scan(repo_info, repo_url)

if __name__ == "__main__":
    main()
