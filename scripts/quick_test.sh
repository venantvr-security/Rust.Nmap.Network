#!/bin/bash
# =============================================================================
# IDS Lab - Test rapide d'un lab
# =============================================================================

IDS=${1:-suricata}

echo "🔍 Test rapide du lab $IDS"
echo ""

# Trouver l'IP de la cible
TARGET=$(docker inspect target_${IDS} --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)

if [ -z "$TARGET" ]; then
    echo "❌ Cible non trouvée. Le lab $IDS est-il démarré?"
    echo ""
    echo "Démarrez-le avec:"
    echo "  cd /home/rvv/Bureau/Rust.Nmap.Network/${IDS}-lab && docker compose up -d"
    exit 1
fi

echo "✅ Cible trouvée: $TARGET"
echo ""

# Test de connectivité
echo "📍 Test 1: Ping"
ping -c 1 $TARGET >/dev/null 2>&1 && echo "   ✅ Ping OK" || echo "   ⚠️ Ping bloqué (normal)"

echo ""
echo "📍 Test 2: Port scan (80)"
nc -zv -w2 $TARGET 80 2>&1 | head -1

echo ""
echo "📍 Test 3: Nmap SYN scan"
sudo nmap -sS -p 80 --max-retries 1 -T4 $TARGET 2>/dev/null | grep -E "(PORT|80/)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Interfaces disponibles:"
echo ""
docker network ls | grep -E "(snort|suricata|zeek)"
echo ""
echo "Pour voir les alertes:"
echo "  - EveBox: http://localhost:5636 (Suricata)"
echo "  - Logs: docker logs ${IDS}_ids -f"
