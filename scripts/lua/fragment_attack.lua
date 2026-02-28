#!/usr/bin/env lua5.3
-- =============================================================================
-- IDS Lab - Attaque par fragmentation IP
-- =============================================================================
-- Ce script démontre des techniques d'évasion IDS par fragmentation.
--
-- NOTE: Pour des tests plus avancés (fragments superposés, manipulation TTL),
-- utilisez la version Python avec Scapy: scripts/legacy/fragment_attack.py
--
-- TECHNIQUES TESTÉES:
-- 1. Scan standard (référence)
-- 2. Fragmentation -f (8 bytes)
-- 3. Fragmentation --mtu 16
-- 4. Fragmentation --mtu 24
-- 5. Scan décoy (leurres)
-- 6. Timing lent (T1)
--
-- USAGE:
--   lua5.3 fragment_attack.lua [TARGET_IP] [OPTIONS]
--
-- OPTIONS:
--   --quick      Tests rapides uniquement
--   -h, --help   Afficher cette aide
-- =============================================================================

package.path = package.path .. ";./lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local OPTIONS = {
    quick = false,
}

-- Chemin du projet
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)

-- =============================================================================
-- FONCTIONS
-- =============================================================================

local function get_suricata_ip()
    local cmd = "docker inspect target_suricata --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null"
    local output, exit_code = T.run(cmd)
    if exit_code == 0 and output ~= "" then
        return output:gsub("%s+", "")
    end
    return nil
end

local function run_scan(name, cmd)
    print("")
    print(T.colors.bold .. "📍 " .. name .. T.colors.reset)

    local output, exit_code = T.run(cmd .. " 2>/dev/null")

    if exit_code == 0 then
        for line in output:gmatch("[^\n]+") do
            if line:match("^PORT") or line:match("^%d+/") or line:match("open")
               or line:match("filtered") or line:match("closed") then
                print("   " .. line)
            end
        end
    else
        print("   " .. T.colors.yellow .. "Échec ou timeout" .. T.colors.reset)
    end
end

local function test_standard(target)
    run_scan(
        "Test 1: SYN Scan standard (référence)",
        string.format("sudo nmap -sS -p 80 --max-retries 1 -T4 %s", target)
    )
end

local function test_fragment_f(target)
    run_scan(
        "Test 2: Fragmentation -f (8 bytes)",
        string.format("sudo nmap -f -sS -p 80 --max-retries 1 -T4 %s", target)
    )
end

local function test_fragment_mtu16(target)
    run_scan(
        "Test 3: Fragmentation --mtu 16",
        string.format("sudo nmap --mtu 16 -sS -p 80 --max-retries 1 -T4 %s", target)
    )
end

local function test_fragment_mtu24(target)
    run_scan(
        "Test 4: Fragmentation --mtu 24",
        string.format("sudo nmap --mtu 24 -sS -p 80 --max-retries 1 -T4 %s", target)
    )
end

local function test_decoy(target)
    run_scan(
        "Test 5: Scan avec decoys (leurres)",
        string.format("sudo nmap -D RND:5 -sS -p 80 --max-retries 1 -T4 %s", target)
    )
end

local function test_slow(target)
    print("")
    print(T.colors.bold .. "📍 Test 6: Timing très lent (T1)" .. T.colors.reset)
    print("   (timeout 15s - T1 est très lent)")

    local cmd = string.format("timeout 15 sudo nmap -T1 -sS -p 80 --max-retries 0 %s 2>/dev/null", target)
    local output, _ = T.run(cmd)

    local found = false
    for line in output:gmatch("[^\n]+") do
        if line:match("open") or line:match("filtered") or line:match("closed") then
            print("   " .. line)
            found = true
        end
    end

    if not found then
        print("   " .. T.colors.yellow .. "Timeout (normal pour T1)" .. T.colors.reset)
    end
end

local function show_results()
    print("")
    print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)
    print(T.colors.green .. "✅ Tests terminés!" .. T.colors.reset)
    print("")
    print(T.colors.bold .. "💡 Interprétation:" .. T.colors.reset)
    print("   - Niveau 1-3: La fragmentation devrait passer")
    print("   - Niveau 4-5: La fragmentation devrait être détectée")
    print("")
    print(T.colors.bold .. "📊 Vérifiez les alertes:" .. T.colors.reset)
    print("   - EveBox: http://localhost:5636")
    print("   - Kibana: http://localhost:5601")
    print("")
    print(T.colors.bold .. "🔬 Pour des tests avancés:" .. T.colors.reset)
    print("   - Fragments superposés (overlapping)")
    print("   - Manipulation TTL")
    print("   Utilisez: sudo python3 scripts/legacy/fragment_attack.py")
    print("")
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    local target = nil

    -- Parse arguments
    for i = 1, #arg do
        if arg[i] == "-h" or arg[i] == "--help" then
            print([[
Usage: lua5.3 fragment_attack.lua [TARGET_IP] [OPTIONS]

Arguments:
  TARGET_IP    IP de la cible (auto-détecté si non spécifié)

Options:
  --quick      Tests rapides uniquement (skip T1)
  -h, --help   Afficher cette aide

Techniques testées:
  1. Scan standard (référence)
  2. Fragmentation -f (8 bytes)
  3. Fragmentation --mtu 16
  4. Fragmentation --mtu 24
  5. Scan décoy (leurres)
  6. Timing lent (T1)

Exemple:
  sudo lua5.3 fragment_attack.lua 172.29.0.100
  sudo lua5.3 fragment_attack.lua --quick

Note: Pour des tests plus avancés (fragments superposés, TTL),
utilisez: sudo python3 scripts/legacy/fragment_attack.py
]])
            os.exit(0)
        elseif arg[i] == "--quick" then
            OPTIONS.quick = true
        elseif not arg[i]:match("^%-") then
            target = arg[i]
        end
    end

    -- Auto-détecter la cible
    if not target then
        target = get_suricata_ip()
        if target then
            print(T.colors.cyan .. "🎯 Cible auto-détectée: " .. target .. T.colors.reset)
        end
    end

    if not target then
        print([[
Usage: lua5.3 fragment_attack.lua [TARGET_IP]

Auto-détection échouée. Spécifiez l'IP de la cible:
  lua5.3 fragment_attack.lua 172.29.0.100

Ou démarrez le lab Suricata:
  cd suricata-lab && docker compose up -d
]])
        os.exit(1)
    end

    -- Header
    print(T.colors.cyan .. T.colors.bold)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║            Attaque par Fragmentation IP                      ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(string.format("║  Target: %-51s ║", target))
    print("╚══════════════════════════════════════════════════════════════╝")
    print(T.colors.reset)

    -- Vérifier les privilèges
    local uid_output, _ = T.run("id -u")
    local uid = tonumber(uid_output:gsub("%s+", "")) or 1000

    if uid ~= 0 then
        T.log_warning("Ce script nécessite les privilèges root pour les scans SYN")
        print("   Relancez avec: sudo lua5.3 fragment_attack.lua " .. target)
        print("")
    end

    -- Tests
    test_standard(target)
    test_fragment_f(target)
    test_fragment_mtu16(target)
    test_fragment_mtu24(target)
    test_decoy(target)

    if not OPTIONS.quick then
        test_slow(target)
    else
        print("")
        print(T.colors.yellow .. "   Test T1 ignoré (--quick)" .. T.colors.reset)
    end

    show_results()
end

main()
