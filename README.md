# Secure AI Proxy – LLM Security Platform

Secure AI Proxy est un projet personnel de cybersécurité visant à
protéger les intégrations LLM (ChatGPT, Claude) contre les attaques
de type prompt injection, jailbreak et fuites de données sensibles.

## Objectif
Simuler un proxy de sécurité SOC pour LLM en environnement entreprise.

## Fonctionnalités clés
- Détection prompt injection & jailbreak (EN/FR)
- Data Leak Prevention (emails, CB, API keys, IBAN…)
- Sanitization automatique des prompts
- Logs sécurité et monitoring ELK Stack
- Modes enforce / monitor / dry-run

## Stack
Python 3.11 · FastAPI · Regex & rules engine · ELK Stack · Docker

## Cas d’usage
- Employés utilisant ChatGPT en entreprise
- Prévention RGPD & audit sécurité
- Analyse forensics SOC

➡️ Documentation technique complète : `/docs/README_full.md`
