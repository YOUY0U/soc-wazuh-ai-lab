# 🛡️ Mini-SOC personnel Wazuh augmenté par IA

## 📘 Introduction
Ce projet a pour objectif de concevoir et déployer un **mini-SOC (Security Operations Center)** personnel afin de renforcer mes compétences en **Blue Team**, **DevSecOps** et **IA appliquée à la cybersécurité**.  
L'idée est de bâtir une architecture réaliste, inspirée des SOC d'entreprise, mais hébergée sur un **home-lab Proxmox**.  

Le projet combine :
- **Wazuh** (SIEM open-source basé sur ELK)
- **Sysmon & Auditd** pour la collecte des logs
- **Python + IA (OpenAI / scikit-learn)** pour l'analyse intelligente des alertes

L'objectif final est d'automatiser la **détection, la corrélation et la priorisation** d'événements de sécurité, tout en offrant un environnement de simulation d'attaques et de réponse aux incidents.

---

## 🏗️ Architecture globale
         ┌────────────────────────┐
         │   Wazuh Manager        │
         │ + Indexer + Dashboard  │
         └────────────┬───────────┘
                      │
  ┌───────────────────┼───────────────────┐
  │                   │                   │
  ┌─────▼──────┐ ┌─────▼──────┐ ┌─────▼──────┐
│ Windows │ │ Linux │ │ VM │
│ Agent │ │ Agent │ │ Vulnérable │
│ Sysmon + │ │ Auditd + │ │ DVWA / │
│ Wazuh │ │ Wazuh │ │ Metaspl. │
└────────────┘ └────────────┘ └────────────┘
│
┌─────▼──────┐
│ Module IA │
│ (Python) │
│ - Résumé │
│ - Anomalies│
└────────────┘

### 💡 Environnement
- Hyperviseur : **Proxmox VE 8**
- OS principal : **Ubuntu Server 22.04**
- VMs :
  - `wazuh-manager` → Manager + Indexer + Dashboard
  - `win-endpoint` → Windows 10 + Sysmon + Wazuh Agent
  - `linux-endpoint` → Ubuntu + auditd + Wazuh Agent
  - `dvwa-lab` → Application vulnérable DVWA

---

## ⚙️ Stack technique

| Domaine | Technologie | Rôle |
|----------|--------------|------|
| SIEM | **Wazuh** | Supervision, corrélation, alerting |
| Logs | **Sysmon, Auditd, OSQuery** | Collecte des événements endpoint |
| Infrastructure | **Docker, Proxmox** | Virtualisation et orchestration |
| IA / ML | **Python, OpenAI API, scikit-learn, PyOD** | Analyse intelligente des alertes |
| Dashboard | **Wazuh Dashboard / Grafana** | Visualisation et reporting |
| Test d'attaque | **Metasploitable, DVWA** | Génération d'événements pour détection |
| Automatisation | **n8n / Python scripts** | Extraction et traitement des données |

---

## 🧰 Déploiement

### 1. Installation du Wazuh Stack
Sur la VM Ubuntu principale :
```bash
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker
docker compose up -d
