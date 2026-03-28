# GFW IP List Project

## Project Overview

This repository contains IP address lists for GFW (Great Firewall) blocked services. These lists can be used to configure routing tables to route traffic through VPN.

## Directory Structure

```
/home/steamedfish/work/gfwiplist/
├── README.md              # Main documentation (English)
├── README.zh-CN.md        # Chinese documentation
├── gfwiplist.txt          # Generated IP list file
├── misc/
│   ├── generate.py        # Python script to generate IP lists from various sources
│   ├── gfwdomainlist.txt  # Domain list for potentially polluted CDN domains
│   └── requirements.txt   # Python dependencies
├── .github/
│   └── workflows/
│       └── refresh-gfwiplist.yml  # GitHub Actions workflow for automated refresh
├── .gitignore             # Git ignore patterns
└── AGENTS.md              # This file

```

## File Purposes

### Root Directory

- **gfwiplist.txt**: The main output file containing IP ranges for blocked services (Twitter, Facebook, Google, etc.)

### misc/ Directory

- **generate.py**: Python script that fetches IP ranges from various sources:
  - AWS IP ranges (via AWS official API)
  - Cloudflare IP ranges
  - GitHub IP ranges (via GitHub API)
  - AS number lookups (via whois.radb.net)
  
- **gfwdomainlist.txt**: List of CDN domains that may serve polluted content

- **requirements.txt**: Python package dependencies

### .github/workflows/ Directory

- **refresh-gfwiplist.yml**: GitHub Actions workflow that:
  - Runs weekly (every Sunday at 00:00 UTC) to refresh the IP list
  - Runs on push when generate.py, requirements.txt, or the workflow itself changes
  - Supports manual trigger via "Run workflow" button in GitHub Actions UI
  - Prevents commit loops by only committing when actual changes are detected
  - Uses `[skip ci]` in commit messages to avoid triggering itself

## Development Guidelines

### Code Style

- Python code follows PEP 8
- Type hints are required for function parameters and return values
- Docstrings follow Google style format

### Python Dependencies

```bash
cd misc
pip install -r requirements.txt
```

Required packages:
- python-whois: For AS number lookups
- netaddr: For IP network operations
- jinja2: For template rendering
- requests: For HTTP API calls

## TODO

No active tasks.

## CHANGELOG

### 2025-03-29

- Added feature to fetch China IP list from mayaxcn/china-ip-list repository
- Implemented automatic filtering of China domestic IP ranges from GFW list
- Added block-based processing to preserve output structure (headers, comments)
- Implemented CIDR merging within blocks while keeping blocks separate
- Added sub-block processing: each service section (like "### AMAZON ###", "### EC2 ###") is filtered and merged independently
- Added IPv6 support for China IP filtering
- Updated generate.py with `fetch_china_ip_list()`, `parse_and_filter_blocks()`, and `filter_and_merge_content()` functions

### 2025-03-28

- Fixed Python type hint syntax errors (List[] brackets)
- Added docstrings to cf2cidr() and gh2cidr() functions
- Added missing 'requests' dependency to requirements.txt
- Created .gitignore for Python project
- Created AGENTS.md documentation
- Created GitHub Actions workflow for automated weekly refresh
- Added push-triggered refresh for code changes
