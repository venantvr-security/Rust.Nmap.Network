#!/bin/bash
# =============================================================================
# IDS Lab - Test automatisé des 5 niveaux de sécurité
# =============================================================================

set -e

IDS=${1:-suricata}
TARGET=${2:-$(docker inspect target_${IDS} --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <ids> [target_ip]"
    echo "  ids: snort, suricata, zeek"
    echo ""
    echo "Exemple: $0 suricata"
    exit 1
fi

PROJECT_ROOT="/home/rvv/Bureau/Rust.Nmap.Network"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        Test d'évasion IDS - Tous les niveaux                 ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  IDS: $IDS"
echo "║  Target: $TARGET"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

for level in 1 2 3 4 5; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔒 NIVEAU $level"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Appliquer le template
    case $IDS in
        snort)
            cp "$PROJECT_ROOT/commander/templates/snort/level${level}"* "$PROJECT_ROOT/snort-lab/config/local.rules"
            docker kill -s SIGHUP snort_ids 2>/dev/null || true
            ;;
        suricata)
            cp "$PROJECT_ROOT/commander/templates/suricata/level${level}"* "$PROJECT_ROOT/suricata-lab/rules/local.rules"
            docker kill -s USR2 suricata_ids 2>/dev/null || true
            ;;
        zeek)
            cp "$PROJECT_ROOT/commander/templates/zeek/level${level}"* "$PROJECT_ROOT/zeek-lab/scripts/local.zeek"
            docker restart zeek_ids 2>/dev/null || true
            ;;
    esac

    sleep 2  # Attendre le rechargement

    echo ""
    echo "📍 Test 1: SYN Scan standard"
    sudo nmap -sS -p 80 --max-retries 1 -T4 $TARGET 2>/dev/null | grep -E "(open|filtered|closed)" || echo "Scan terminé"

    echo ""
    echo "📍 Test 2: Scan avec fragmentation"
    sudo nmap -f -sS -p 80 --max-retries 1 -T4 $TARGET 2>/dev/null | grep -E "(open|filtered|closed)" || echo "Scan terminé"

    echo ""
    echo "📍 Test 3: Timing très lent (T1)"
    timeout 10 sudo nmap -T1 -sS -p 80 --max-retries 0 $TARGET 2>/dev/null | grep -E "(open|filtered|closed)" || echo "Timeout (normal pour T1)"

    echo ""
    read -p "Appuyez sur Entrée pour passer au niveau suivant..."
done

echo ""
echo "✅ Test terminé. Consultez EveBox (http://localhost:5636) pour les alertes."
