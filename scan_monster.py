import sys
import json
import requests
import datetime
import argparse
from urllib.parse import urlparse
import time
import logging

# Global variables
base_url = None
tenant_name = None
auth_url = None
iam_base_url = None
auth_token = None
debug = False

# Configure logging
logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s:%(levelname)s:%(message)s')

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
        print("Error: Invalid base_url provided")
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
            print("Successfully authenticated")
        
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
            print(f"Found {len(repo_urls)} repository URLs")
        return repo_urls
    except Exception as e:
        print(f"An error occurred while reading the repository URLs: {e}")
        sys.exit(1)

def get_repo_info(repo_url, github_token=None, gitlab_token=None, bitbucket_token=None, azure_token=None):
    try:
        parsed_url = urlparse(repo_url)
        project_repo_info = {}
        headers = {}
        
        if debug:
            print(f'Identifying project information for repo: {repo_url}')

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
            logging.error(f'Error: Received status code {response.status_code} from {api_url}')
            logging.error(f'Response text: {response.text}')
            return None
        
        response.raise_for_status()
        repo_info = response.json()

        # Determine project_name
        if project_repo_info['platform'] == 'GitHub' or project_repo_info['platform'] == 'GitLab':
            project_repo_info['project_name'] = f"{project_repo_info['platform']}-{repo_info.get('full_name')}"
        elif project_repo_info['platform'] == 'Bitbucket':
            project_repo_info['project_name'] = f"{project_repo_info['platform']}-{repo_info.get('full_name')}"
        elif project_repo_info['platform'] == 'AzureDevOps':
            project_repo_info['project_name'] = f"{project_repo_info['platform']}-{repo_info.get('project', {}).get('name')}-{repo_info.get('name')}"

        if project_repo_info['platform'] == 'GitHub' or project_repo_info['platform'] == 'GitLab':
            project_repo_info['primary_branch'] = repo_info.get('default_branch')
        elif project_repo_info['platform'] == 'Bitbucket':
            project_repo_info['primary_branch'] = repo_info.get('mainbranch', {}).get('name')
        elif project_repo_info['platform'] == 'AzureDevOps':
            project_repo_info['primary_branch'] = repo_info.get('defaultBranch')

        # Extract the branch name from 'refs/heads/' if present
        if 'refs/heads/' in project_repo_info['primary_branch']:
            project_repo_info['primary_branch'] = project_repo_info['primary_branch'].split('refs/heads/')[-1]

        if debug:
            for key, value in project_repo_info.items():
                print(f"{key.replace('_', ' ').title()}: {value}")

        return project_repo_info

    # Most errors will cause an exit(1) but any issues with getting the repo info will just 
    except requests.exceptions.RequestException as e:
        logging.error(f'An error occurred while fetching the repository info for {repo_url}: {e}')
        return None

    except Exception as e:
        logging.error(f'An unexpected error occurred for {repo_url}: {e}')
        return None

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
        
        # Check if the 'projects' key is not None before iterating
        if projects.get('projects') is not None:
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
    if debug:
        print(f"Creating project: {project_name}")
    
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
        print(f"Project {project_name} created successfully with project ID: {project_id}")
    
    return project_id

def start_scan(repo_info, repo_url, scan_types):
    # Build the headers for the request
    headers = {
        'Accept': 'application/json; version=1.0',
        'Authorization': f'Bearer {auth_token}',
        'Content-Type': 'application/json; version=1.0',
        'CorrelationId': ''
    }

    # Initialize the config list
    config = []

    # Append SAST config if requested
    if scan_types.get('sast'):
        sast_config = {
            "type": "sast",
            "value": {}
        }
        # Include the presetName only if provided (i.e. the sast value is not True here)
        if scan_types.get('sast') is not True:
            sast_config["value"]["presetName"] = scan_types['sast']
        config.append(sast_config)

    # Append SCA config if requested
    if scan_types.get('sca'):
        sca_config = {
            "type": "sca",
            "value": {}
        }
        config.append(sca_config)

    # Append IaC config if requested
    if scan_types.get('iac'):
        iac_config = {
            "type": "kics",
            "value": {}
        }
        config.append(iac_config)

    # Append API config if requested and ensure SAST is included
    if scan_types.get('api'):
        api_config = {
            "type": "apisec",
            "value": {}
        }
        config.append(api_config)

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
    
    if debug:
        print(f"Prepared scan configuration for {repo_info['project_name']}")

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

    print(f"Started scan for {repo_info['project_name']}")

def main():
    global base_url
    global tenant_name
    global debug
    global auth_url
    global auth_token
    global iam_base_url

    # Parse and handle various CLI flags
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

    def parse_sast_arg(value):
        if value is None:
            return False
        elif value == '':
            return True
        return value

    parser.add_argument('--sast', nargs='?', const=True, default=False, type=parse_sast_arg, help='Enable SAST scan. Optionally specify a SAST preset.')
    parser.add_argument('--sca', action='store_true', help='Enable SCA scan.')
    parser.add_argument('--iac', action='store_true', help='Enable IaC scan.')
    parser.add_argument('--api', action='store_true', help='Enable API scan.')
    parser.add_argument('--space_scans', type=int, help='Number of minutes to wait between scans')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args()
    base_url = args.base_url
    tenant_name = args.tenant_name
    github_token = args.github_token
    gitlab_token = args.gitlab_token
    bitbucket_token = args.bitbucket_token
    azure_token = args.azure_token
    debug = args.debug
    
    scan_types = {
        'sast': args.sast,
        'sca': args.sca,
        'iac': args.iac,
        'api': args.api
    }

    # If no scan types are specified, default to all scan types
    if not any(scan_types.values()):
        scan_types = {k: True for k in scan_types}
    
    # If an API scan is requested, ensure that a SAST scan is also enabled
    if scan_types.get('api') and not scan_types.get('sast'):
        scan_types['sast'] = True
    
    # Read in repos
    repo_urls = read_repo_urls(args.repo_file)
    
    # Provide output to the user
    enabled_scans = ', '.join([k.upper() for k, v in scan_types.items() if v])
    print(f"Initiating scanning process on {len(repo_urls)} repositories using the following engine(s): {enabled_scans}")

    if debug and scan_types.get('sast'):
        if scan_types.get('sast') is not True:
            print(f"SAST scan will use the preset '{scan_types['sast']}'")
        else:
            print(f"SAST scan will use the default preset")
        
    # Authenticate to CxOne
    if args.iam_base_url:
        iam_base_url = args.iam_base_url
    
    auth_url = generate_auth_url()
    auth_token = authenticate(args.api_key)
    
    if auth_token is None:
        return
    
    errors = 0
    started = 0
    
    # Iterate through repos to check if projects exist, create projects (if necessary), and start scans
    for index, repo_url in enumerate(repo_urls):
        if(debug):
            print(f"Preparing to scan repository {index + 1} of {len(repo_urls)}: {repo_url}")
    
        repo_info = get_repo_info(repo_url, github_token, gitlab_token, bitbucket_token, azure_token)
        
        if repo_info is None:
            errors += 1
            print(f"Encountered error fetching info from repository {repo_url}; error logged")
            continue  # Skip to the next repository if repo_info is None
        
        repo_info['projectId'] = check_project_exists(repo_info['project_name'])

        if repo_info['projectId'] is None:
            repo_info['projectId'] = create_project(repo_info['project_name'], repo_url, repo_info['primary_branch'])

        start_scan(repo_info, repo_url, scan_types)
        started += 1

        # If space_scans is set and it's not the last repository, wait the specified time
        if args.space_scans and index < len(repo_urls) - 1:
            if debug:
                print(f"Waiting {args.space_scans} minute(s) before starting the next scan...")
            time.sleep(args.space_scans * 60)  # Wait time is in seconds, so multiply by 60
    
    if errors > 0:
        print(f"Errors encountered with {errors} repositories; check error log for details")
    
    print(f"Successfully started {started} scans")

if __name__ == "__main__":
    main()
