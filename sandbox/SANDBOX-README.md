# SANDBOX README for High Assurance DID WEB

## Introduction

This directory contains instructions and practical examples to create a high assurance ```did:web```

## CONTROLS and MAPPING

Definition of technical controls for high assurance did:webs and mapping to levels of assurance.

[Defining and Mapping Controls](./CONTROLS.md)

## SETUP

Step by step instructions to setup a high assurance did:web: 

[High Assurance DID:WEB Setup](SETUP.md)

## VERIFICATION

Steps on how to [Verify](./VERIFYING.md).

## Notes on Setting Up a Sandbox Environment

This repository includes hands-on examples to gain practical experience for implementation. A few experimental Python scripts are provided in the scripts directory. To prepare, clone this repo into a working directory.

If you wish to run these scripts it is advisable that you set up a 'sandbox' or a virtual environment. You then need to activate this environment and install the dependencies.

To set up your virtual environment and run the scripts run the following in your working directory.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd scripts
python Demo.py
```

## Prototype App

A prototype app has been created using FastAPI. Once you have the dependencies installed and the environment configured you can run the prototype

```bash
# Switch to the sandbox directory
% cd sandbox
% uvicorn app.main:app --reload
INFO:     Will watch for changes in these directories: ['/Users/trbouma/projects/cira/sandbox']
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [52551] using StatReload
INFO:     Started server process [52553]
INFO:     Waiting for application startup.
INFO:     Application startup complete.

```

## Key Resources and Prior Work

This project builds on and leverages prior work

* [IETF DRAFT Leveraging DNS in Digital Trust: Credential Exchanges and Trust Registries](https://www.ietf.org/id/draft-latour-dns-and-digital-trust-01.html)
* [CIRA A trust layer for the internet is emerging: a 2023 report](https://www.cira.ca/en/resources/documents/state-of-internet/a-trust-layer-for-the-internet-is-emerging-a-2023-report/)
* [CIRA A Trust Layer for the Internet is Emerging](https://www.cira.ca/uploads/2023/12/12222023_A-trust-layer-for-the-internet-is-emerging_-report-%E2%80%93-Continuum_CIRA.pdf)
* [TrustyDID](https://github.com/CIRALabs/TrustyDID)
* [W3C Data Integrity 1.0](https://www.w3.org/community/reports/credentials/CG-FINAL-data-integrity-20220722/)

