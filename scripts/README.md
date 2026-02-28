# Scripts IDS Lab

Ce répertoire contient les scripts utilitaires pour les labs IDS.

## Structure

```
scripts/
├── lua/                        # Scripts Lua (recommandé)
│   ├── lib/
│   │   └── test_utils.lua      # Utilitaires partagés
│   ├── start_all_labs.lua      # Démarrer tous les labs
│   ├── stop_all_labs.lua       # Arrêter tous les labs
│   ├── quick_test.lua          # Test rapide de connectivité
│   ├── scan_all_levels.lua     # Test des 5 niveaux de sécurité
│   └── fragment_attack.lua     # Tests d'évasion par fragmentation
└── legacy/                     # Scripts legacy (bash/python)
    ├── start_all_labs.sh
    ├── stop_all_labs.sh
    ├── quick_test.sh
    ├── scan_all_levels.sh
    └── fragment_attack.py      # Version Scapy (plus avancée)
```

## Prérequis

```bash
sudo apt install lua5.3 nmap
```

## Usage

### Gestion des Labs

```bash
cd scripts/lua

# Démarrer tous les labs IDS
lua5.3 start_all_labs.lua

# Avec Kibana (ELK Stack)
lua5.3 start_all_labs.lua --with-kibana

# Arrêter tous les labs
lua5.3 stop_all_labs.lua
```

### Test Rapide

```bash
# Test par défaut (suricata)
lua5.3 quick_test.lua

# Test d'un lab spécifique
lua5.3 quick_test.lua snort
lua5.3 quick_test.lua zeek
```

### Test des Niveaux de Sécurité

```bash
# Test interactif (attend entre chaque niveau)
lua5.3 scan_all_levels.lua suricata

# Test automatique (sans attente)
lua5.3 scan_all_levels.lua suricata --auto

# Avec IP cible spécifique
lua5.3 scan_all_levels.lua snort 172.28.0.100
```

### Tests d'Évasion (Fragmentation)

```bash
# Version Lua (nmap)
sudo lua5.3 fragment_attack.lua

# Avec cible spécifique
sudo lua5.3 fragment_attack.lua 172.29.0.100

# Test rapide (skip timing lent)
sudo lua5.3 fragment_attack.lua --quick

# Version Python avancée (Scapy)
# Pour: fragments superposés, manipulation TTL
sudo python3 legacy/fragment_attack.py 172.29.0.100
```

## Scripts Disponibles

| Script | Description |
|--------|-------------|
| `start_all_labs.lua` | Démarre Snort, Suricata, Zeek (+ Kibana optionnel) |
| `stop_all_labs.lua` | Arrête tous les labs |
| `quick_test.lua` | Test ping, ports, nmap d'un lab |
| `scan_all_levels.lua` | Test des 5 niveaux de règles IDS |
| `fragment_attack.lua` | Tests d'évasion par fragmentation IP |

## Techniques d'Évasion Testées

### fragment_attack.lua
1. Scan SYN standard (référence)
2. Fragmentation -f (8 bytes)
3. Fragmentation --mtu 16
4. Fragmentation --mtu 24
5. Scan avec decoys (leurres)
6. Timing très lent (T1)

### fragment_attack.py (legacy, plus avancé)
- Fragments IP manuels avec Scapy
- Fragments superposés (overlapping)
- Manipulation TTL

## URLs d'Accès

| Service | URL |
|---------|-----|
| Dashboard Commander | http://localhost:3000 |
| Kibana | http://localhost:5601 |
| EveBox (Suricata) | http://localhost:5636 |
| Elasticsearch | http://localhost:9200 |
| Snort Editor | http://localhost:8081 |
| Suricata Editor | http://localhost:8082 |
| Zeek Editor | http://localhost:8083 |

## IPs des Cibles

| Lab | IP Cible | Sous-réseau |
|-----|----------|-------------|
| Snort | 172.28.0.100 | 172.28.0.0/24 |
| Suricata | 172.29.0.100 | 172.29.0.0/24 |
| Zeek | 172.30.0.100 | 172.30.0.0/24 |
