# Security Policy

## Overview

This repository provides a fork of pkcs11-proxy with native TLS and
mutual TLS (mTLS) support. Security is a primary design goal, but this
project has **not** undergone a formal third‑party audit.

------------------------------------------------------------------------

## Reporting a Vulnerability

**Please do NOT open public GitHub issues for security
vulnerabilities.**

Preferred reporting methods:

-   GitHub Security Advisories (private disclosure)

Please include:

-   Description of the issue and potential impact
-   Steps to reproduce or proof-of-concept
-   Affected versions and configuration
-   Logs with secrets removed

### Response expectations

We aim to:

-   Acknowledge reports within **72 hours**
-   Provide status updates during investigation
-   Coordinate responsible disclosure once a fix is available

------------------------------------------------------------------------

## Supported Versions

Security fixes are generally provided for:

-   The latest release
-   Recent tagged versions (best effort)

Older forks or heavily modified downstream builds may not be supported.

------------------------------------------------------------------------

## Security Model (Summary)

This fork adds encrypted transport to pkcs11-proxy.

Key properties:

-   TLS 1.2 minimum
-   Optional mutual TLS authentication
-   Hostname/IP verification
-   Optional CRL checking

A deeper technical security description is available in:

    docs/security.md

------------------------------------------------------------------------

## Scope

In scope:

-   TLS transport layer
-   Client/server proxy communication

Out of scope:

-   Underlying PKCS#11 provider or HSM
-   Operating system security
-   Compromise of hosts running the software
