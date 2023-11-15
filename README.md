# Scan Monster Usage Guide

## Summary

Scan Monster is a powerful automation tool for initiating scans on multiple repositories using the Checkmarx One APIs. It supports several types of scans, including SAST, SCA, IaC, and API, with the flexibility to specify scan presets and intervals between scans. Designed for ad hoc scan operations, it simplifies bulk vulnerability assessments across codebases.

1. Install nessesary dependencies for python
   ex: $ pip install requests
2. create repos.txt file that has the repos you want to scan listed line by line
   ex: $ https://github.com/appsecco/dvja
3. Do not edit the scan_monster.py file, only put your arguments in the command


## Syntax and Arguments

Execute the script using the following command line:

```bash
python scan_monster.py --base_url BASE_URL --tenant_name TENANT_NAME --api_key API_KEY --repo_file REPO_FILE [OPTIONS]
```

### Required Arguments

- `--base_url`: The base URL of the Checkmarx One region.
- `--tenant_name`: Your tenant name in Checkmarx One.
- `--api_key`: Your API key for authenticating with the Checkmarx One APIs.
- `--repo_file`: Path to a file containing a list of repository URLs to scan.

### Optional Arguments

- `--iam_base_url`: Optional IAM base URL. Defaults to the same as `base_url` if not provided.
- `--github_token`: Personal access token for GitHub repositories.
- `--gitlab_token`: Personal access token for GitLab repositories.
- `--bitbucket_token`: Personal access token for Bitbucket repositories.
- `--azure_token`: Personal access token for Azure DevOps repositories.
- `--sast [SAST_PRESET]`: Enable SAST scan with an optional preset name.
- `--sca`: Enable SCA scan. (Flag, no value required)
- `--iac`: Enable IaC scan. (Flag, no value required)
- `--api`: Enable API scan. (Flag, no value required)
- `--space_scans MINUTES`: Define a waiting period in minutes between each scan.
- `--debug`: Enable debug output. (Flag, no value required)

## Usage Examples

Initiate all types of scans on repositories listed in the file:

```bash
python scan_monster.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --repo_file repos.txt
```

Initiate SAST and SCA scans with a preset for SAST:

```bash
python scan_monster.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --repo_file repos.txt --sast "MyCustomPreset" --sca
```

Initiate scans with a waiting period of 5 minutes between each scan:

```bash
python scan_monster.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --repo_file repos.txt --space_scans 5
```

Initiate scans with debug output:

```bash
python scan_monster.py --base_url https://cxone.example.com --tenant_name mytenant --api_key 12345 --repo_file repos.txt --debug
```

## Output

Scan Monster will output the status of each scan initiation and any errors encountered during the process. If debug mode is enabled, it will provide detailed information about the scan configurations and the response from the Checkmarx One APIs.
