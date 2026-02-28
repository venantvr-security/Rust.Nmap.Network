#!/usr/bin/env lua5.3
-- =============================================================================
-- IDS Lab - Arrêter tous les labs
-- =============================================================================
-- Ce script arrête tous les labs IDS:
-- - Snort Lab
-- - Suricata Lab
-- - Zeek Lab
-- - Kibana Lab
--
-- OPTIONS:
--   -h, --help    Afficher cette aide
-- =============================================================================

package.path = package.path .. ";./lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local LABS = {"snort", "suricata", "zeek", "kibana"}

-- Chemin du projet
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)

-- =============================================================================
-- FONCTIONS
-- =============================================================================

local function parse_args()
    for i = 1, #arg do
        if arg[i] == "-h" or arg[i] == "--help" then
            print([[
Usage: lua5.3 stop_all_labs.lua

Arrête tous les labs IDS (Snort, Suricata, Zeek, Kibana).
]])
            os.exit(0)
        end
    end
end

local function print_header()
    print(T.colors.cyan .. T.colors.bold)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║               Arrêt de tous les labs IDS                     ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(T.colors.reset)
    print("")
end

local function stop_lab(lab_name)
    local lab_dir = PROJECT_ROOT .. "/" .. lab_name .. "-lab"

    -- Vérifier si le répertoire existe
    local check_cmd = string.format("test -d '%s'", lab_dir)
    if not T.run_ok(check_cmd) then
        return true  -- Pas de répertoire = pas de lab à arrêter
    end

    T.log_info("Arrêt du lab " .. lab_name .. "...")

    local ok = T.docker_compose_down(lab_dir)
    if ok then
        T.log_success(lab_name .. " arrêté")
        return true
    else
        T.log_warning(lab_name .. " n'était pas démarré")
        return true  -- Pas une erreur
    end
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    parse_args()
    print_header()

    for _, lab in ipairs(LABS) do
        stop_lab(lab)
    end

    print("")
    print(T.colors.green .. "✅ Tous les labs sont arrêtés" .. T.colors.reset)
end

main()
