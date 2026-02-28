#!/bin/bash
# =============================================================================
# TEST DU KIBANA LAB - ELK Stack pour visualisation IDS
# =============================================================================
# Ce script teste le bon fonctionnement du stack ELK:
# - Elasticsearch: stockage et recherche
# - Kibana: visualisation
# - Filebeat: collecte des logs IDS
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIBANA_LAB="$PROJECT_ROOT/kibana-lab"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Vérifier les prérequis
check_prerequisites() {
    log_info "Vérification des prérequis..."

    if ! command -v docker &> /dev/null; then
        log_error "docker n'est pas installé"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_error "curl n'est pas installé"
        exit 1
    fi

    if [ ! -d "$KIBANA_LAB" ]; then
        log_error "kibana-lab directory not found: $KIBANA_LAB"
        exit 1
    fi

    log_success "Prérequis OK"
}

# Démarrer kibana-lab
start_kibana_lab() {
    log_info "Démarrage du kibana-lab..."

    cd "$KIBANA_LAB"
    docker compose down --remove-orphans 2>/dev/null || true
    docker compose up -d 2>&1 | tail -5

    # Attendre qu'Elasticsearch soit prêt (healthcheck)
    log_info "Attente d'Elasticsearch (max 120s)..."
    local timeout=120
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status":"green"\|"status":"yellow"'; then
            log_success "Elasticsearch est healthy"
            break
        fi
        sleep 5
        ((elapsed+=5))
        echo -ne "\r  Attente... ${elapsed}s"
    done
    echo ""

    if [ $elapsed -ge $timeout ]; then
        log_error "Timeout: Elasticsearch n'est pas prêt"
        return 1
    fi
}

# Tester Elasticsearch
test_elasticsearch() {
    log_info "=== Test Elasticsearch ==="

    # Health check
    local health=$(curl -s http://localhost:9200/_cluster/health 2>/dev/null)
    if echo "$health" | grep -q '"status":"green"\|"status":"yellow"'; then
        local status=$(echo "$health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        log_success "Elasticsearch status: $status"
    else
        log_error "Elasticsearch health check failed"
        return 1
    fi

    # Cluster info
    local cluster_name=$(curl -s http://localhost:9200 2>/dev/null | grep -o '"cluster_name" *: *"[^"]*"' | cut -d'"' -f4)
    log_info "Cluster name: $cluster_name"

    # Version
    local version=$(curl -s http://localhost:9200 2>/dev/null | grep -o '"number" *: *"[^"]*"' | head -1 | cut -d'"' -f4)
    log_info "Version: $version"

    log_success "Elasticsearch OK"
}

# Tester Kibana
test_kibana() {
    log_info "=== Test Kibana ==="

    # Attendre que Kibana soit prêt
    log_info "Attente de Kibana (max 120s)..."
    local timeout=120
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local status_code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5601/api/status 2>/dev/null)
        if [ "$status_code" = "200" ]; then
            log_success "Kibana répond (HTTP 200)"
            break
        fi
        sleep 5
        ((elapsed+=5))
        echo -ne "\r  Attente... ${elapsed}s (HTTP $status_code)"
    done
    echo ""

    if [ $elapsed -ge $timeout ]; then
        log_error "Timeout: Kibana n'est pas prêt"
        return 1
    fi

    # Vérifier le status
    local kibana_status=$(curl -s http://localhost:5601/api/status 2>/dev/null | grep -o '"state":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ "$kibana_status" = "green" ]; then
        log_success "Kibana status: $kibana_status"
    else
        log_warning "Kibana status: $kibana_status"
    fi

    log_success "Kibana OK"
}

# Tester Filebeat
test_filebeat() {
    log_info "=== Test Filebeat ==="

    # Vérifier que le container est running
    if docker ps --format '{{.Names}}' | grep -q "kibana_filebeat"; then
        log_success "Container kibana_filebeat est running"
    else
        log_error "Container kibana_filebeat n'est pas running"
        return 1
    fi

    # Attendre que Filebeat indexe des données (max 30s)
    log_info "Attente de l'indexation Filebeat (max 60s)..."
    local timeout=60
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local indices=$(curl -s 'http://localhost:9200/_cat/indices?format=json' 2>/dev/null)
        local count=$(echo "$indices" | grep -o '"docs.count":"[0-9]*"' | grep -o '[0-9]*' | awk '{s+=$1} END {print s}')
        count=${count:-0}
        if [ "$count" -gt 0 ]; then
            log_success "Documents indexés: $count"
            break
        fi
        sleep 5
        ((elapsed+=5))
        echo -ne "\r  Attente indexation... ${elapsed}s"
    done
    echo ""

    if [ $elapsed -ge $timeout ]; then
        log_warning "Pas de documents indexés (les logs IDS sont peut-être vides)"
    fi

    log_success "Filebeat OK"
}

# Tester les indices
test_indices() {
    log_info "=== Test des indices ==="

    # Lister les indices
    local indices=$(curl -s 'http://localhost:9200/_cat/indices?v' 2>/dev/null)
    echo "$indices"

    # Vérifier la présence des indices IDS
    local suricata_count=$(curl -s 'http://localhost:9200/suricata-*/_count' 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
    local snort_count=$(curl -s 'http://localhost:9200/snort-*/_count' 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*')
    local zeek_count=$(curl -s 'http://localhost:9200/zeek-*/_count' 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*')

    suricata_count=${suricata_count:-0}
    snort_count=${snort_count:-0}
    zeek_count=${zeek_count:-0}

    echo ""
    log_info "Documents par IDS:"
    echo "  - Suricata (suricata-*): $suricata_count docs"
    echo "  - Snort (snort-*): $snort_count docs"
    echo "  - Zeek (zeek-*): $zeek_count docs"

    local total=$((suricata_count + snort_count + zeek_count))
    if [ "$total" -gt 0 ]; then
        log_success "Total: $total documents indexés"
    else
        log_warning "Aucun document indexé (démarrer un IDS lab et générer du trafic)"
    fi
}

# Générer du trafic de test (optionnel)
generate_test_traffic() {
    log_info "=== Génération de trafic de test ==="

    # Vérifier si un IDS lab est running
    local ids_running=false
    local target_ip=""

    if docker ps --format '{{.Names}}' | grep -q "suricata_ids"; then
        ids_running=true
        target_ip="172.29.0.100"
        log_info "Suricata lab détecté, cible: $target_ip"
    elif docker ps --format '{{.Names}}' | grep -q "snort_ids"; then
        ids_running=true
        target_ip="172.28.0.100"
        log_info "Snort lab détecté, cible: $target_ip"
    elif docker ps --format '{{.Names}}' | grep -q "zeek_ids"; then
        ids_running=true
        target_ip="172.30.0.100"
        log_info "Zeek lab détecté, cible: $target_ip"
    fi

    if [ "$ids_running" = true ] && command -v nmap &> /dev/null; then
        log_info "Lancement d'un scan nmap rapide..."
        nmap -sT -p 22,80 "$target_ip" -T4 --max-retries 1 2>/dev/null | grep -E "^PORT|^[0-9]"
        log_success "Scan terminé"

        # Attendre l'indexation
        sleep 5
        log_info "Vérification de l'indexation..."
        test_indices
    else
        log_warning "Aucun IDS lab running ou nmap non disponible"
        log_info "Pour générer du trafic: démarrer un IDS lab puis relancer ce test"
    fi
}

# Arrêter kibana-lab
stop_kibana_lab() {
    log_info "Arrêt du kibana-lab..."
    cd "$KIBANA_LAB"
    docker compose down --remove-orphans 2>/dev/null
    log_success "kibana-lab arrêté"
}

# Afficher l'aide
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-stop     Ne pas arrêter le lab après les tests"
    echo "  --with-ids    Démarrer aussi Suricata pour générer des logs"
    echo "  --quick       Test rapide (skip génération de trafic)"
    echo "  -h, --help    Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0                    # Test complet puis arrêt"
    echo "  $0 --no-stop          # Test et laisser running"
    echo "  $0 --with-ids         # Démarrer Suricata + Kibana + test"
}

# Main
main() {
    local no_stop=false
    local with_ids=false
    local quick=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-stop)
                no_stop=true
                shift
                ;;
            --with-ids)
                with_ids=true
                shift
                ;;
            --quick)
                quick=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Option inconnue: $1"
                show_help
                exit 1
                ;;
        esac
    done

    echo "============================================"
    echo "  TEST KIBANA LAB - ELK Stack"
    echo "============================================"
    echo ""

    check_prerequisites

    # Optionnellement démarrer un IDS lab
    if [ "$with_ids" = true ]; then
        log_info "Démarrage du lab Suricata pour générer des logs..."
        cd "$PROJECT_ROOT/suricata-lab"
        docker compose up -d 2>&1 | tail -3
        sleep 10
    fi

    # Tests principaux
    start_kibana_lab
    test_elasticsearch
    test_kibana
    test_filebeat
    test_indices

    # Génération de trafic (sauf en mode quick)
    if [ "$quick" = false ]; then
        generate_test_traffic
    fi

    # Cleanup
    if [ "$no_stop" = false ]; then
        echo ""
        stop_kibana_lab

        if [ "$with_ids" = true ]; then
            log_info "Arrêt du lab Suricata..."
            cd "$PROJECT_ROOT/suricata-lab"
            docker compose down --remove-orphans 2>/dev/null
        fi
    else
        echo ""
        log_info "Lab laissé running (--no-stop)"
        log_info "Kibana: http://localhost:5601"
        log_info "Elasticsearch: http://localhost:9200"
    fi

    echo ""
    echo "============================================"
    echo "  TESTS TERMINÉS"
    echo "============================================"
}

main "$@"
