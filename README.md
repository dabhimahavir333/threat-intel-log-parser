# Threat Intelligence Log Parser

## Overview
An automated Python-based security tool designed to ingest web server logs, parse out IP addresses using Regular Expressions, and cross-reference them against the AbuseIPDB Threat Intelligence API. 

## Objectives
* Automate the extraction of indicators of compromise (IoCs) from raw Apache/Nginx logs.
* Reduce manual SOC analyst fatigue by enriching IP data automatically.
* Generate structured JSON/CSV reports of malicious actors based on threat confidence scores.

## Architecture
* **Language:** Python 3.x
* **Core Libraries:** `re` (regex processing), `requests` (API integration), `argparse` (CLI execution).
  
