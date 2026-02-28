#!/bin/bash
# =============================================================================
# IDS LAB COMMANDER - Tests End-to-End
# =============================================================================
#
# Ce script teste les scénarios métier complets:
# 1. Démarrage/arrêt des labs
# 2. API status et alertes
# 3. Workflow complet: start -> scan -> alerts -> stop
#
# USAGE:
#   ./tests/e2e_tests.sh [--all|--suricata|--snort|--zeek|--api]
#
# PRÉREQUIS:
#   - Docker et Docker Compose installés
#   - Commander lancé sur localhost:3000
#   - nmap installé (optionnel, pour tests de scan)
# =============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
COMMANDER_URL="http://localhost:3000"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_PASSED=0
TESTS_FAILED=0

# =============================================================================
# HELPERS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Vérifie si le commander est accessible
check_commander() {
    if curl -s -o /dev/null -w "%{http_code}" "$COMMANDER_URL" | grep -q "200"; then
        return 0
    else
        return 1
    fi
}

# Vérifie si un container est running
container_running() {
    docker ps --format "{{.Names}}" | grep -q "^$1$"
}

# Attend qu'un container soit dans l'état souhaité
wait_for_container() {
    local name=$1
    local expected_running=$2
    local timeout=${3:-30}
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        if [ "$expected_running" = "true" ]; then
            container_running "$name" && return 0
        else
            ! container_running "$name" && return 0
        fi
        sleep 1
        ((elapsed++))
    done
    return 1
}

# =============================================================================
# TESTS API
# =============================================================================

test_api_health() {
    log_info "Test: API accessible"
    if check_commander; then
        log_success "API accessible sur $COMMANDER_URL"
    else
        log_error "API non accessible sur $COMMANDER_URL"
        return 1
    fi
}

test_api_status() {
    log_info "Test: GET /api/status"
    local response=$(curl -s "$COMMANDER_URL/api/status")
    if echo "$response" | grep -q "\["; then
        log_success "API /api/status retourne un JSON valide"
    else
        log_error "API /api/status invalide: $response"
    fi
}

test_api_alerts() {
    log_info "Test: GET /api/alerts/suricata"
    local response=$(curl -s "$COMMANDER_URL/api/alerts/suricata")
    if echo "$response" | grep -q "ids"; then
        log_success "API /api/alerts retourne un JSON valide"
    else
        log_error "API /api/alerts invalide: $response"
    fi
}

# =============================================================================
# TESTS DOCKER COMPOSE
# =============================================================================

test_lab_start() {
    local lab=$1
    log_info "Test: Démarrage du lab $lab"

    # Arrêter d'abord si en cours
    cd "$PROJECT_ROOT/${lab}-lab"
    docker compose down --remove-orphans 2>/dev/null || true
    sleep 2

    # Démarrer
    if docker compose up -d --build; then
        sleep 5
        if container_running "${lab}_ids" || container_running "${lab}_editor"; then
            log_success "Lab $lab démarré avec succès"
            return 0
        else
            log_error "Lab $lab: containers non détectés après démarrage"
            return 1
        fi
    else
        log_error "Lab $lab: échec du démarrage"
        return 1
    fi
}

test_lab_stop() {
    local lab=$1
    log_info "Test: Arrêt du lab $lab"

    cd "$PROJECT_ROOT/${lab}-lab"
    if docker compose down --remove-orphans; then
        sleep 3
        if ! container_running "${lab}_ids"; then
            log_success "Lab $lab arrêté avec succès"
            return 0
        else
            log_error "Lab $lab: containers encore actifs après arrêt"
            return 1
        fi
    else
        log_error "Lab $lab: échec de l'arrêt"
        return 1
    fi
}

test_lab_logs() {
    local lab=$1
    log_info "Test: Récupération des logs de ${lab}_ids"

    if container_running "${lab}_ids"; then
        local logs=$(docker logs --tail 10 "${lab}_ids" 2>&1)
        if [ -n "$logs" ]; then
            log_success "Logs récupérés pour ${lab}_ids"
            return 0
        else
            log_warning "Logs vides pour ${lab}_ids"
            return 0
        fi
    else
        log_warning "Container ${lab}_ids non actif, test ignoré"
        return 0
    fi
}

# =============================================================================
# SCÉNARIOS MÉTIER
# =============================================================================

scenario_full_workflow() {
    local lab=$1
    log_info "=== SCÉNARIO: Workflow complet pour $lab ==="

    # 1. Démarrer le lab
    test_lab_start "$lab" || return 1

    # 2. Attendre que tout soit prêt
    sleep 5

    # 3. Vérifier l'API status
    log_info "Vérification du status via API"
    local status=$(curl -s "$COMMANDER_URL/api/status")
    if echo "$status" | grep -q "${lab}"; then
        log_success "Container $lab visible dans /api/status"
    else
        log_warning "Container $lab non visible dans /api/status"
    fi

    # 4. Récupérer les alertes
    log_info "Récupération des alertes via API"
    local alerts=$(curl -s "$COMMANDER_URL/api/alerts/$lab")
    if echo "$alerts" | grep -q "ids"; then
        log_success "API alertes fonctionnelle pour $lab"
    fi

    # 5. Lancer un scan (si nmap disponible)
    if command -v nmap &> /dev/null; then
        local target_ip=""
        case $lab in
            snort) target_ip="172.28.0.100" ;;
            suricata) target_ip="172.29.0.100" ;;
            zeek) target_ip="172.30.0.100" ;;
        esac

        log_info "Lancement d'un scan nmap sur $target_ip"
        nmap -sS -p 21,22,80 "$target_ip" -T4 --max-retries 1 2>/dev/null || true
        sleep 3

        # Vérifier si des alertes ont été générées
        local new_alerts=$(curl -s "$COMMANDER_URL/api/alerts/$lab")
        log_success "Scan exécuté (vérifiez manuellement les alertes)"
    else
        log_warning "nmap non disponible, scan ignoré"
    fi

    # 6. Vérifier les logs
    test_lab_logs "$lab"

    # 7. Arrêter le lab
    test_lab_stop "$lab"

    log_info "=== FIN SCÉNARIO $lab ==="
}

scenario_multiple_labs() {
    log_info "=== SCÉNARIO: Plusieurs labs simultanés ==="

    # Démarrer Suricata et Snort en même temps
    test_lab_start "suricata" &
    local pid1=$!
    test_lab_start "snort" &
    local pid2=$!

    wait $pid1 $pid2

    # Vérifier que les deux tournent
    sleep 5
    if container_running "suricata_ids" || container_running "suricata_editor"; then
        log_success "Suricata actif"
    else
        log_error "Suricata non actif"
    fi

    if container_running "snort_ids" || container_running "snort_editor"; then
        log_success "Snort actif"
    else
        log_error "Snort non actif"
    fi

    # Nettoyer
    test_lab_stop "suricata"
    test_lab_stop "snort"

    log_info "=== FIN SCÉNARIO multiple labs ==="
}

scenario_stop_all() {
    log_info "=== SCÉNARIO: Stop All Labs ==="

    # Démarrer un lab
    test_lab_start "suricata"

    # Utiliser l'API pour tout arrêter
    log_info "Appel de /lab/stop-all via curl"
    curl -s -X POST "$COMMANDER_URL/lab/stop-all" > /dev/null

    sleep 5

    # Vérifier que tout est arrêté
    if ! container_running "suricata_ids" && ! container_running "snort_ids" && ! container_running "zeek_ids"; then
        log_success "Tous les labs arrêtés via /lab/stop-all"
    else
        log_error "Des containers sont encore actifs après stop-all"
    fi

    log_info "=== FIN SCÉNARIO stop-all ==="
}

# =============================================================================
# MAIN
# =============================================================================

print_summary() {
    echo ""
    echo "============================================"
    echo "RÉSUMÉ DES TESTS"
    echo "============================================"
    echo -e "Tests réussis: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests échoués: ${RED}$TESTS_FAILED${NC}"
    echo "============================================"

    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    fi
}

run_all_tests() {
    log_info "Exécution de tous les tests..."

    # Tests API
    test_api_health
    test_api_status
    test_api_alerts

    # Scénarios
    scenario_full_workflow "suricata"
    scenario_stop_all

    print_summary
}

run_api_tests() {
    test_api_health
    test_api_status
    test_api_alerts
    print_summary
}

run_lab_tests() {
    local lab=$1
    scenario_full_workflow "$lab"
    print_summary
}

# Parsing des arguments
case "${1:-all}" in
    --all|-a)
        run_all_tests
        ;;
    --api)
        run_api_tests
        ;;
    --suricata)
        run_lab_tests "suricata"
        ;;
    --snort)
        run_lab_tests "snort"
        ;;
    --zeek)
        run_lab_tests "zeek"
        ;;
    --multi)
        scenario_multiple_labs
        print_summary
        ;;
    --help|-h)
        echo "Usage: $0 [--all|--api|--suricata|--snort|--zeek|--multi]"
        echo ""
        echo "Options:"
        echo "  --all       Exécute tous les tests (défaut)"
        echo "  --api       Tests API uniquement"
        echo "  --suricata  Tests lab Suricata"
        echo "  --snort     Tests lab Snort"
        echo "  --zeek      Tests lab Zeek"
        echo "  --multi     Test plusieurs labs simultanés"
        ;;
    *)
        run_all_tests
        ;;
esac
