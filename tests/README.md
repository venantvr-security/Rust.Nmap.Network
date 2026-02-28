# Tests IDS Lab

Ce répertoire contient les tests pour les labs IDS.

## Structure

```
tests/
├── lua/                    # Tests en Lua (recommandé)
│   ├── lib/
│   │   └── test_utils.lua  # Utilitaires de test
│   ├── run_all.lua         # Runner principal
│   ├── test_snort.lua      # Test Snort Lab
│   ├── test_suricata.lua   # Test Suricata Lab
│   ├── test_zeek.lua       # Test Zeek Lab
│   └── test_kibana.lua     # Test Kibana Lab (ELK)
└── sh/                     # Tests en Bash (legacy)
    ├── e2e_tests.sh
    ├── nmap_detection_test.sh
    └── kibana_lab_test.sh
```

## Prérequis

### Lua 5.3
```bash
sudo apt install lua5.3
```

### Outils
- Docker et Docker Compose
- nmap
- curl

## Usage

### Tests Lua

```bash
cd tests/lua

# Tous les tests
lua5.3 run_all.lua

# Un seul test
lua5.3 run_all.lua snort

# Plusieurs tests
lua5.3 run_all.lua snort suricata

# Options
lua5.3 run_all.lua --no-stop      # Laisser les labs running
lua5.3 run_all.lua --quick        # Tests rapides
lua5.3 run_all.lua --list         # Lister les tests

# Test individuel avec options
lua5.3 test_snort.lua --no-start  # Lab déjà running
lua5.3 test_snort.lua --no-stop   # Ne pas arrêter après
lua5.3 test_snort.lua --help      # Aide
```

### Tests Bash (legacy)

```bash
cd tests/sh

# Détection nmap
./nmap_detection_test.sh [snort|suricata|zeek|all]

# Test Kibana
./kibana_lab_test.sh [--no-stop] [--with-ids] [--quick]
```

## Options communes

| Option | Description |
|--------|-------------|
| `--no-start` | Ne pas démarrer le lab (utiliser un lab déjà running) |
| `--no-stop` | Ne pas arrêter le lab après les tests |
| `--quick` | Tests rapides (skip certains scans) |
| `--help` | Afficher l'aide |

## Comportement

Chaque test:
1. Démarre le lab (`docker compose up`)
2. Attend l'initialisation de l'IDS
3. Génère du trafic (scans nmap)
4. Vérifie les logs/alertes
5. Arrête le lab (`docker compose down`)

Avec `--no-stop`, le lab reste accessible après le test.

## Cibles

| Lab | IP Cible | Ports |
|-----|----------|-------|
| Snort | 172.28.0.100 | 21, 22, 80, 8080 |
| Suricata | 172.29.0.100 | 21, 22, 80, 8080 |
| Zeek | 172.30.0.100 | 21, 22, 80, 8080 |
| Kibana | localhost | 5601 (Kibana), 9200 (ES) |
