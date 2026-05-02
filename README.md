# Cloud-Based SQL Injection Detection System

## Overview
A cloud-based web application that detects and logs SQL injection 
attacks in real time, deployed on AWS infrastructure.

## AWS Services Used
- **EC2** — Hosts the Flask web application
- **RDS (MySQL)** — Stores users and attack logs
- **IAM** — Manages secure access permissions
- **CloudWatch** — Monitors EC2 and RDS activity

## Tech Stack
- Python 3
- Flask
- PyMySQL
- AWS (EC2, RDS, IAM, CloudWatch)

## How It Works
1. User submits login or signup form
2. Input is scanned against SQL injection regex patterns
3. If attack detected → input is blocked and logged to RDS
4. If clean → normal login/signup proceeds

## Setup Instructions
1. Clone the repo
   git clone https://github.com/Gunjan-Yadav12/cloud_based_sql_injection_detection_system.git
2. Create a .env file based on .env.example
3. Install dependencies
   pip install -r requirements.txt
4. Run the app
   python app.py

## Security Note
Never commit real credentials. Use .env for all sensitive values.
