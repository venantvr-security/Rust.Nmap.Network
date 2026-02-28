#!/bin/bash
# =============================================================================
# IDS Lab - Démarrer tous les labs
# =============================================================================

PROJECT_ROOT="/home/rvv/Bureau/Rust.Nmap.Network"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Démarrage de tous les labs IDS                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

for lab in snort suricata zeek; do
    echo "🚀 Démarrage du lab $lab..."
    cd "$PROJECT_ROOT/${lab}-lab"
    docker compose up -d 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "   ✅ $lab démarré"
    else
        echo "   ❌ Erreur lors du démarrage de $lab"
    fi
done

echo ""
echo "⏳ Attente du démarrage des containers..."
sleep 5

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Status des containers:"
echo ""
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(NAME|snort|suricata|zeek|target|evebox)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "IPs des cibles:"
echo ""
for target in target_snort target_suricata target_zeek; do
    IP=$(docker inspect $target --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
    if [ -n "$IP" ]; then
        echo "  $target: $IP"
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Accès:"
echo "  Dashboard: http://localhost:3000"
echo "  EveBox:    http://localhost:5636"
echo "  Snort:     http://localhost:8081"
echo "  Suricata:  http://localhost:8082"
echo "  Zeek:      http://localhost:8083"
