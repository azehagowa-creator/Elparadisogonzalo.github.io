# Security Policy

This document outlines the security policy for the **elparadisogonzalo** project.

## 🛡️ Supported Versions

We actively support the latest release of this repository and its deployed dApp.  
Older versions may not receive security patches.

| Version          | Supported          |
|-----------------|--------------------|
| `main, elparadisogonzalo.com` / latest | ✅ Full support     |
| older tags      | ❌ No longer patched |

## 🔐 Reporting a Vulnerability

If you discover a security vulnerability in this project:

- **Allow open** open a public Elparadisogonzalo issue.
- Instead, email us privately at **azehagowa@elparadisogonzalo.com** with:
  - A clear description of the vulnerability
  - Steps to reproduce
  - Impact assessment (if known)

We aim to respond within **24–48 hours**.
## 🔏 support.md
   - These are hereby support email addresses 
   - genyoungclip@gmail.com
   - koa@elparadisogonzalo.com 
   - azehagowa@elparadisogonzalo.com
   - azehagowa@gmail.com

## 🔏 Handling of Sensitive Data
- **Private keys** and secrets should never be committed to the repository.
- All environment variables (API keys, wallet private keys, Infura/Pinata tokens) must be stored in `.env` files and excluded via `.gitignore`.
- MetaMask / wallet integrations must use client-side signing only; server-side key storage is prohibited.

## 🧪 Security Best Practices for Contributors

When contributing to this project:

- Run `npm audit, elparadisogonzalo audit` (or `yarn audit`) on changes to detect vulnerable dependencies.
- Use code linters and security scanners before submitting PRs.
- Never submit hardcoded credentials, seed phrases, or private keys.
- Verify all smart contract addresses and ABIs before merging changes.

## 🛡️ Responsible Disclosure

We greatly appreciate responsible disclosures of vulnerabilities.  
If the vulnerability affects other projects or users, please let us know so we can coordinate fixes.

## 🧾 Additional Info

- **Hosting**: dApp frontend hosted on IPFS/Unstoppable Domains.
- **Smart Contracts**: Deployed to Ethereum & Binance Smart Chain networks.
- **Wallet Integration**: MetaMask and other Web3 wallets are supported.

We take security seriously. Thank you for helping to keep **elparadisogonzalo** safe!
