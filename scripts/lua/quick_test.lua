#!/usr/bin/env lua5.3
-- =============================================================================
-- IDS Lab - Test rapide d'un lab
-- =============================================================================
-- Ce script teste rapidement la connectivité et les services d'un lab IDS.
--
-- USAGE:
--   lua5.3 quick_test.lua [IDS]
--
-- ARGUMENTS:
--   IDS    Le lab à tester: snort, suricata, zeek (défaut: suricata)
--
-- OPTIONS:
--   -h, --help    Afficher cette aide
-- =============================================================================

package.path = package.path .. ";./lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local IDS_CONFIG = {
    snort = {
        target = "target_snort",
        ip = "172.28.0.100",
        ports = {21, 22, 80, 8080},
        editor = "http://localhost:8081",
    },
    suricata = {
        target = "target_suricata",
        ip = "172.29.0.100",
        ports = {21, 22, 80, 8080},
        editor = "http://localhost:8082",
        evebox = "http://localhost:5636",
    },
    zeek = {
        target = "target_zeek",
        ip = "172.30.0.100",
        ports = {21, 22, 80, 8080},
        editor = "http://localhost:8083",
    },
}

-- Chemin du projet
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)

-- =============================================================================
-- FONCTIONS
-- =============================================================================

local function get_container_ip(container_name)
    local cmd = string.format(
        "docker inspect %s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null",
        container_name
    )
    local output, exit_code = T.run(cmd)
    if exit_code == 0 and output ~= "" then
        return output:gsub("%s+", "")
    end
    return nil
end

local function test_ping(target)
    T.log_info("Test 1: Ping")
    local cmd = string.format("ping -c 1 -W 2 %s", target)
    local _, exit_code = T.run(cmd)
    if exit_code == 0 then
        T.log_success("Ping OK")
        return true
    else
        T.log_warning("Ping bloqué (normal pour certains IDS)")
        return true  -- Pas une erreur
    end
end

local function test_port(target, port)
    local cmd = string.format("nc -zv -w2 %s %d 2>&1", target, port)
    local output, exit_code = T.run(cmd)
    return exit_code == 0, output
end

local function test_ports(target, ports)
    T.log_info("Test 2: Ports scan (nc)")

    for _, port in ipairs(ports) do
        local ok, _ = test_port(target, port)
        local status = ok and T.colors.green .. "open" .. T.colors.reset
                          or T.colors.yellow .. "closed/filtered" .. T.colors.reset
        print(string.format("   Port %d: %s", port, status))
    end
end

local function test_nmap(target)
    T.log_info("Test 3: Nmap SYN scan")

    -- Essayer avec sudo d'abord
    local cmd = string.format("sudo nmap -sS -p 80 --max-retries 1 -T4 %s 2>/dev/null", target)
    local output, exit_code = T.run(cmd)

    if exit_code ~= 0 then
        -- Fallback sur TCP connect
        cmd = string.format("nmap -sT -p 80 --max-retries 1 -T4 %s 2>/dev/null", target)
        output, _ = T.run(cmd)
    end

    -- Extraire les lignes pertinentes
    for line in output:gmatch("[^\n]+") do
        if line:match("^PORT") or line:match("^%d+/") then
            print("   " .. line)
        end
    end
end

local function show_access_info(ids_name, config)
    print("")
    print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)
    print(T.colors.bold .. "Interfaces disponibles:" .. T.colors.reset)
    print("")

    local networks_output, _ = T.run("docker network ls | grep -E '(snort|suricata|zeek)'")
    print(networks_output)

    print("")
    print(T.colors.bold .. "Pour voir les alertes:" .. T.colors.reset)

    if config.evebox then
        print("  - EveBox: " .. config.evebox)
    end

    print("  - Logs: docker logs " .. ids_name .. "_ids -f")

    if config.editor then
        print("  - Editor: " .. config.editor)
    end

    print("")
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    -- Parse arguments
    local ids_name = "suricata"  -- Défaut

    for i = 1, #arg do
        if arg[i] == "-h" or arg[i] == "--help" then
            print([[
Usage: lua5.3 quick_test.lua [IDS]

Arguments:
  IDS    Le lab à tester: snort, suricata, zeek (défaut: suricata)

Options:
  -h, --help    Afficher cette aide

Exemple:
  lua5.3 quick_test.lua suricata
  lua5.3 quick_test.lua snort
]])
            os.exit(0)
        elseif not arg[i]:match("^%-") then
            ids_name = arg[i]
        end
    end

    -- Vérifier que l'IDS est valide
    local config = IDS_CONFIG[ids_name]
    if not config then
        T.log_error("IDS inconnu: " .. ids_name)
        print("IDS disponibles: snort, suricata, zeek")
        os.exit(1)
    end

    print(T.colors.cyan .. T.colors.bold)
    print("🔍 Test rapide du lab " .. ids_name)
    print(T.colors.reset)
    print("")

    -- Trouver l'IP de la cible
    local target = get_container_ip(config.target)

    if not target then
        T.log_error("Cible non trouvée. Le lab " .. ids_name .. " est-il démarré?")
        print("")
        print("Démarrez-le avec:")
        print(string.format("  cd %s/%s-lab && docker compose up -d", PROJECT_ROOT, ids_name))
        os.exit(1)
    end

    T.log_success("Cible trouvée: " .. target)
    print("")

    -- Tests
    test_ping(target)
    print("")
    test_ports(target, config.ports)
    print("")
    test_nmap(target)

    -- Infos d'accès
    show_access_info(ids_name, config)
end

main()
