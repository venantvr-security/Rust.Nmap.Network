# Rust.Nmap.Network - IDS Lab Commander

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Nmap](https://img.shields.io/badge/Nmap-0E83CD?style=for-the-badge&logo=nmap&logoColor=white)](https://nmap.org/)
[![Snort](https://img.shields.io/badge/Snort-E4003A?style=for-the-badge&logo=snort&logoColor=white)](https://www.snort.org/)
[![Suricata](https://img.shields.io/badge/Suricata-EF6C00?style=for-the-badge&logo=suricata&logoColor=white)](https://suricata.io/)
[![Zeek](https://img.shields.io/badge/Zeek-2D5B96?style=for-the-badge&logo=zeek&logoColor=white)](https://zeek.org/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-2C2D72?style=for-the-badge&logo=python&logoColor=white)](https://scapy.net/)

Laboratoire académique de test d'évasion IDS avec interface de pilotage complète.

## Architecture

```mermaid
graph TB
    subgraph LOCALHOST["LOCALHOST (Attaquant)"]
        COMMANDER["Commander :3000"]
        NMAP["Nmap / Scapy / Hping3"]
    end

    subgraph SNORT_NET["snort_net"]
        SNORT_IDS["snort_ids"]
        TARGET_SNORT["target_snort nginx:80"]
        SNORT_EDITOR["editor :8081"]
    end

    subgraph SURICATA_NET["suricata_net"]
        SURICATA_IDS["suricata_ids"]
        TARGET_SURICATA["target_suricata nginx:80"]
        SURICATA_EDITOR["editor :8082"]
        EVEBOX["evebox :5636"]
    end

    subgraph ZEEK_NET["zeek_net"]
        ZEEK_IDS["zeek_ids"]
        TARGET_ZEEK["target_zeek nginx:80"]
        ZEEK_EDITOR["editor :8083"]
    end

    COMMANDER --> SNORT_NET
    COMMANDER --> SURICATA_NET
    COMMANDER --> ZEEK_NET
    NMAP --> TARGET_SNORT
    NMAP --> TARGET_SURICATA
    NMAP --> TARGET_ZEEK
```

## Quick Start

### 1. Configuration initiale (une seule fois)

```bash
# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER
newgrp docker

# Vérifier
docker ps  # Doit fonctionner sans sudo
```

### 2. Démarrer les labs

```bash
# Tous les labs
./scripts/start_all_labs.sh

# Ou un seul lab
cd suricata-lab && docker compose up -d
```

### 3. Démarrer le Commander

```bash
cd commander
cargo run
```

### 4. Ouvrir le dashboard

http://localhost:3000

## Interfaces Web

| Port | Service | Description |
|------|---------|-------------|
| 3000 | Commander | Dashboard principal, templates, cookbook |
| 5636 | EveBox | Visualisation alertes Suricata |
| 8081 | Filebrowser | Édition règles Snort |
| 8082 | Filebrowser | Édition règles Suricata |
| 8083 | Filebrowser | Édition scripts Zeek |

## Niveaux de Sécurité

Le dashboard permet de basculer entre 5 niveaux de règles pour chaque IDS:

| Niveau | Nom | Description |
|--------|-----|-------------|
| 1 | Minimal | Très perméable, détecte uniquement les attaques évidentes |
| 2 | Basic | Détecte les scans courants (SYN, NULL, XMAS) |
| 3 | Moderate | Équilibré, idéal pour tester l'évasion |
| 4 | Strict | Haute sensibilité, détecte la fragmentation |
| 5 | Paranoid | Sécurité maximum, alerte sur presque tout |

## Scripts d'attaque

```bash
# Test rapide d'un lab
./scripts/quick_test.sh suricata

# Test de tous les niveaux
./scripts/scan_all_levels.sh suricata

# Attaque par fragmentation (Scapy)
sudo python3 ./scripts/fragment_attack.py 172.19.0.3
```

## Techniques d'évasion testables

### Fragmentation IP
```bash
sudo nmap -f TARGET_IP              # Fragmentation simple
sudo nmap -f -f --mtu 8 TARGET_IP   # Fragmentation max
```

### Timing
```bash
sudo nmap -T0 TARGET_IP   # Très lent (évite seuils)
sudo nmap -T1 TARGET_IP   # Lent
```

### Decoys
```bash
sudo nmap -D RND:10 TARGET_IP       # 10 decoys aléatoires
sudo nmap -D decoy1,decoy2 TARGET   # Decoys spécifiques
```

### Source port
```bash
sudo nmap --source-port 53 TARGET_IP   # Port DNS (souvent autorisé)
sudo nmap --source-port 80 TARGET_IP   # Port HTTP
```

## Structure du projet

```
Rust.Nmap.Network/
├── commander/
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── templates/          # 5 niveaux x 3 IDS
│       ├── snort/
│       ├── suricata/
│       └── zeek/
├── snort-lab/
│   ├── docker-compose.yml
│   └── config/
├── suricata-lab/
│   ├── docker-compose.yml
│   ├── rules/
│   └── logs/
├── zeek-lab/
│   ├── docker-compose.yml
│   └── scripts/
├── scripts/                # Scripts d'attaque
│   ├── start_all_labs.sh
│   ├── stop_all_labs.sh
│   ├── quick_test.sh
│   ├── scan_all_levels.sh
│   └── fragment_attack.py
└── README.md
```

## Workflow académique suggéré

1. **Comprendre**: Lire les règles au niveau 3 (Moderate)
2. **Tester**: Lancer un scan nmap standard, observer les alertes
3. **Analyser**: Identifier quelle règle a déclenché l'alerte
4. **Évader**: Tester des techniques (fragmentation, timing, decoys)
5. **Comparer**: Passer au niveau 4, retester les mêmes techniques
6. **Documenter**: Noter quelles techniques évitent quels niveaux

## Troubleshooting

### Docker sans sudo
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Règles ne se rechargent pas
```bash
# Forcer manuellement
docker kill -s SIGHUP snort_ids
docker kill -s USR2 suricata_ids
docker restart zeek_ids
```

### Container ne démarre pas
```bash
docker logs snort_ids
docker logs suricata_ids
```

## Liens utiles

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Snort 3 Rules](https://docs.snort.org/rules/)
- [Suricata Rules](https://docs.suricata.io/en/latest/rules/)
- [Zeek Scripts](https://docs.zeek.org/en/master/scripting/)
