#!/usr/bin/env lua5.3
-- =============================================================================
-- IDS Lab - Démarrer tous les labs
-- =============================================================================
-- Ce script démarre tous les labs IDS en parallèle:
-- - Snort Lab (172.28.0.0/24)
-- - Suricata Lab (172.29.0.0/24)
-- - Zeek Lab (172.30.0.0/24)
-- - Kibana Lab (172.31.0.0/24) [optionnel]
--
-- OPTIONS:
--   --with-kibana    Démarrer aussi Kibana Lab (ELK Stack)
--   -h, --help       Afficher cette aide
-- =============================================================================

package.path = package.path .. ";./lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local LABS = {
    {name = "snort",    target = "target_snort",    ip = "172.28.0.100"},
    {name = "suricata", target = "target_suricata", ip = "172.29.0.100"},
    {name = "zeek",     target = "target_zeek",     ip = "172.30.0.100"},
}

local KIBANA_LAB = {name = "kibana", target = nil, ip = "localhost"}

local OPTIONS = {
    with_kibana = false,
}

-- Chemin du projet
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)

-- =============================================================================
-- FONCTIONS
-- =============================================================================

local function parse_args()
    for i = 1, #arg do
        if arg[i] == "--with-kibana" then
            OPTIONS.with_kibana = true
        elseif arg[i] == "-h" or arg[i] == "--help" then
            print([[
Usage: lua5.3 start_all_labs.lua [OPTIONS]

Options:
  --with-kibana    Démarrer aussi Kibana Lab (ELK Stack)
  -h, --help       Afficher cette aide

Exemple:
  lua5.3 start_all_labs.lua              # Labs IDS uniquement
  lua5.3 start_all_labs.lua --with-kibana  # Avec Kibana
]])
            os.exit(0)
        end
    end
end

local function print_header()
    print(T.colors.cyan .. T.colors.bold)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              Démarrage de tous les labs IDS                  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(T.colors.reset)
    print("")
end

local function start_lab(lab)
    local lab_dir = PROJECT_ROOT .. "/" .. lab.name .. "-lab"

    T.log_info("Démarrage du lab " .. lab.name .. "...")

    local ok = T.docker_compose_up(lab_dir)
    if ok then
        T.log_success(lab.name .. " démarré")
        return true
    else
        T.log_error("Erreur lors du démarrage de " .. lab.name)
        return false
    end
end

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

local function show_status()
    print("")
    print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)
    print(T.colors.bold .. "Status des containers:" .. T.colors.reset)
    print("")

    local output, _ = T.run("docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep -E '(NAME|snort|suricata|zeek|target|evebox|kibana|elasticsearch|filebeat)'")
    print(output)

    print("")
    print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)
    print(T.colors.bold .. "IPs des cibles:" .. T.colors.reset)
    print("")

    for _, lab in ipairs(LABS) do
        local ip = get_container_ip(lab.target)
        if ip then
            print(string.format("  %s: %s", lab.target, ip))
        end
    end

    print("")
    print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)
    print(T.colors.bold .. "Accès:" .. T.colors.reset)
    print("  Dashboard:     http://localhost:3000")
    print("  EveBox:        http://localhost:5636")
    print("  Snort Editor:  http://localhost:8081")
    print("  Suricata Edit: http://localhost:8082")
    print("  Zeek Editor:   http://localhost:8083")

    if OPTIONS.with_kibana then
        print("  Kibana:        http://localhost:5601")
        print("  Elasticsearch: http://localhost:9200")
    end

    print("")
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    parse_args()
    print_header()

    local labs_to_start = {}
    for _, lab in ipairs(LABS) do
        table.insert(labs_to_start, lab)
    end

    if OPTIONS.with_kibana then
        table.insert(labs_to_start, KIBANA_LAB)
    end

    -- Démarrer tous les labs
    local success_count = 0
    for _, lab in ipairs(labs_to_start) do
        if start_lab(lab) then
            success_count = success_count + 1
        end
    end

    -- Attendre le démarrage
    print("")
    T.log_info("Attente du démarrage des containers...")
    T.sleep(5)

    -- Afficher le status
    show_status()

    print(string.format("%s✅ %d/%d labs démarrés%s",
        T.colors.green, success_count, #labs_to_start, T.colors.reset))
end

main()
