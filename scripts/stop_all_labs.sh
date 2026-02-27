#!/bin/bash
# =============================================================================
# IDS Lab - Arrêter tous les labs
# =============================================================================

PROJECT_ROOT="/home/rvv/Bureau/Rust.Nmap.Network"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               Arrêt de tous les labs IDS                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

for lab in snort suricata zeek; do
    echo "🛑 Arrêt du lab $lab..."
    cd "$PROJECT_ROOT/${lab}-lab"
    docker compose down 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "   ✅ $lab arrêté"
    else
        echo "   ⚠️ $lab n'était pas démarré"
    fi
done

echo ""
echo "✅ Tous les labs sont arrêtés"
