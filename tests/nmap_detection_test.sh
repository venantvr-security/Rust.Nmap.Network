#!/bin/bash
# =============================================================================
# TEST DE DÉTECTION NMAP PAR LES IDS
# =============================================================================
# Ce script teste la capacité de chaque IDS à détecter des scans nmap
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMANDER_URL="http://localhost:3000"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Configurer sudoers pour nmap si nécessaire
setup_sudoers() {
    log_info "Vérification des privilèges sudo pour nmap et docker..."

    # Vérifier si nmap peut s'exécuter avec sudo sans mot de passe
    if ! sudo -n nmap --version &> /dev/null; then
        log_warning "nmap n'est pas configuré pour sudo sans mot de passe"
        echo ""
        echo "Pour configurer sudoers (à exécuter manuellement):"
        echo "  echo \"\$USER ALL=(ALL) NOPASSWD: /usr/bin/nmap\" | sudo tee /etc/sudoers.d/nmap"
        echo "  sudo chmod 440 /etc/sudoers.d/nmap"
        echo ""
        log_warning "Les scans SYN (-sS) seront remplacés par des scans TCP Connect (-sT)"
        return 1
    fi

    # Vérifier si docker peut s'exécuter sans sudo
    if ! docker ps &> /dev/null; then
        if ! sudo -n docker ps &> /dev/null; then
            log_warning "docker nécessite sudo"
            echo ""
            echo "Pour configurer docker sans sudo:"
            echo "  sudo usermod -aG docker \$USER"
            echo "  # Puis déconnectez-vous et reconnectez-vous"
            echo ""
        fi
    fi

    log_success "Privilèges sudo configurés"
    return 0
}

# Vérifier les prérequis
check_prerequisites() {
    log_info "Vérification des prérequis..."

    if ! command -v nmap &> /dev/null; then
        log_error "nmap n'est pas installé"
        echo "  sudo apt install nmap"
        exit 1
    fi

    if ! command -v docker &> /dev/null; then
        log_error "docker n'est pas installé"
        exit 1
    fi

    # Configurer/vérifier sudoers
    setup_sudoers

    if ! curl -s "$COMMANDER_URL/api/health" > /dev/null 2>&1; then
        log_warning "Commander non accessible sur $COMMANDER_URL"
        log_info "Les tests d'API seront ignorés"
    fi

    log_success "Prérequis OK"
}

# Démarrer un lab
start_lab() {
    local lab=$1
    log_info "Démarrage du lab $lab..."

    cd "$PROJECT_ROOT/${lab}-lab"
    docker compose down --remove-orphans 2>/dev/null || true
    docker compose up -d --build 2>&1 | tail -3

    # Attendre que les containers soient prêts
    local timeout=60
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if docker ps --format "{{.Names}}" | grep -q "${lab}_ids\|${lab}_editor"; then
            log_success "Lab $lab démarré"
            sleep 5  # Laisser le temps à l'IDS de s'initialiser
            return 0
        fi
        sleep 2
        ((elapsed+=2))
    done

    log_error "Timeout: lab $lab n'a pas démarré"
    return 1
}

# Arrêter un lab
stop_lab() {
    local lab=$1
    log_info "Arrêt du lab $lab..."
    cd "$PROJECT_ROOT/${lab}-lab"
    docker compose down --remove-orphans 2>/dev/null
    log_success "Lab $lab arrêté"
}

# Lancer un scan nmap
run_nmap_scan() {
    local target=$1
    local scan_type=$2

    log_info "Scan nmap $scan_type sur $target..."

    # Utiliser sudo si disponible, sinon connect scan (-sT)
    local use_sudo=""
    if sudo -n true 2>/dev/null; then
        use_sudo="sudo"
    fi

    case $scan_type in
        "syn")
            if [ -n "$use_sudo" ]; then
                $use_sudo nmap -sS -p 21,22,80,8080 "$target" -T4 --max-retries 1 2>/dev/null
            else
                nmap -sT -p 21,22,80,8080 "$target" -T4 --max-retries 1 2>/dev/null
            fi
            ;;
        "version")
            nmap -sV -p 22,80 "$target" -T4 --max-retries 1 2>/dev/null
            ;;
        "aggressive")
            if [ -n "$use_sudo" ]; then
                $use_sudo nmap -A -p 21,22,80 "$target" -T4 --max-retries 1 2>/dev/null
            else
                nmap -A -p 21,22,80 "$target" -T4 --max-retries 1 2>/dev/null
            fi
            ;;
        "udp")
            if [ -n "$use_sudo" ]; then
                $use_sudo nmap -sU -p 53,161 "$target" -T4 --max-retries 1 2>/dev/null
            else
                log_warning "UDP scan nécessite sudo, ignoré"
            fi
            ;;
        *)
            nmap -sT -p 1-100 "$target" -T4 2>/dev/null
            ;;
    esac

    log_success "Scan $scan_type terminé"
}

# Vérifier les logs de l'IDS
check_ids_logs() {
    local ids=$1
    local container="${ids}_ids"

    log_info "Vérification des logs de $container..."

    # Récupérer les dernières lignes de logs
    local logs=$(docker logs --tail 50 "$container" 2>&1)

    # Chercher des indicateurs d'alertes
    local alert_count=0

    case $ids in
        "snort")
            # Snort écrit les alertes dans un fichier, le lire via docker exec (fichier root)
            alert_count=$(docker exec snort_ids cat /var/log/snort/alert_fast.txt 2>/dev/null | wc -l) || alert_count=0
            alert_count=${alert_count:-0}
            ;;
        "suricata")
            alert_count=$(echo "$logs" | grep -c -i "alert\|drop\|reject" 2>/dev/null) || alert_count=0
            alert_count=${alert_count:-0}
            # Aussi vérifier le fichier eve.json si disponible
            if [ -f "$PROJECT_ROOT/suricata-lab/logs/eve.json" ]; then
                local eve_alerts
                eve_alerts=$(tail -100 "$PROJECT_ROOT/suricata-lab/logs/eve.json" 2>/dev/null | grep -c "alert" 2>/dev/null) || eve_alerts=0
                eve_alerts=${eve_alerts:-0}
                alert_count=$((alert_count + eve_alerts))
            fi
            ;;
        "zeek")
            # Zeek génère des logs structurés (conn.log, notice.log, etc.)
            if [ -f "$PROJECT_ROOT/zeek-lab/logs/conn.log" ]; then
                # Compter les connexions (exclure les headers qui commencent par #)
                alert_count=$(grep -v "^#" "$PROJECT_ROOT/zeek-lab/logs/conn.log" 2>/dev/null | wc -l) || alert_count=0
            else
                # Essayer via docker exec
                alert_count=$(docker exec zeek_ids cat /usr/local/zeek/logs/conn.log 2>/dev/null | grep -v "^#" | wc -l) || alert_count=0
            fi
            alert_count=${alert_count:-0}
            ;;
    esac

    if [ "$alert_count" -gt 0 ]; then
        log_success "$ids: $alert_count entrées de log détectées"
        return 0
    else
        log_warning "$ids: Aucune alerte détectée dans les logs"
        return 1
    fi
}

# Vérifier via l'API
check_api_alerts() {
    local ids=$1

    log_info "Vérification des alertes via API pour $ids..."

    local response=$(curl -s "$COMMANDER_URL/api/alerts/$ids")
    local count=$(echo "$response" | grep -o '"count":[0-9]*' | grep -o '[0-9]*')

    if [ -n "$count" ] && [ "$count" -gt 0 ]; then
        log_success "API: $count alertes pour $ids"
        return 0
    else
        log_warning "API: Aucune alerte pour $ids"
        return 1
    fi
}

# Test complet pour un IDS
test_ids_detection() {
    local ids=$1
    local target=""

    echo ""
    echo "============================================"
    echo "TEST DE DÉTECTION: $ids"
    echo "============================================"

    # Définir l'IP cible
    case $ids in
        "snort") target="172.28.0.100" ;;
        "suricata") target="172.29.0.100" ;;
        "zeek") target="172.30.0.100" ;;
    esac

    # Démarrer le lab
    if ! start_lab "$ids"; then
        log_error "Impossible de démarrer le lab $ids"
        return 1
    fi

    # Attendre que l'IDS soit prêt
    log_info "Attente de l'initialisation de l'IDS..."
    sleep 10

    # Lancer différents types de scans
    log_info "=== Scans nmap ==="

    run_nmap_scan "$target" "syn"
    sleep 2

    run_nmap_scan "$target" "version"
    sleep 2

    run_nmap_scan "$target" "aggressive"
    sleep 3

    # Vérifier les détections
    log_info "=== Vérification des détections ==="

    check_ids_logs "$ids"
    # API check is optional (Commander might not be running)
    check_api_alerts "$ids" || true

    # Afficher un échantillon des logs
    log_info "=== Échantillon des logs ==="
    docker logs --tail 20 "${ids}_ids" 2>&1 | head -15

    # Arrêter le lab
    stop_lab "$ids"

    echo ""
    log_success "Test $ids terminé"
}

# Menu principal
main() {
    echo "============================================"
    echo "  TEST DE DÉTECTION NMAP - IDS LAB"
    echo "============================================"
    echo ""

    check_prerequisites

    case "${1:-all}" in
        "snort")
            test_ids_detection "snort"
            ;;
        "suricata")
            test_ids_detection "suricata"
            ;;
        "zeek")
            test_ids_detection "zeek"
            ;;
        "all")
            test_ids_detection "suricata"
            echo ""
            test_ids_detection "snort"
            echo ""
            test_ids_detection "zeek"
            ;;
        *)
            echo "Usage: $0 [snort|suricata|zeek|all]"
            exit 1
            ;;
    esac

    echo ""
    echo "============================================"
    echo "  TESTS TERMINÉS"
    echo "============================================"
}

main "$@"
