#!/usr/bin/env lua5.3
-- =============================================================================
-- IDS Lab - Test automatisé des 5 niveaux de sécurité
-- =============================================================================
-- Ce script teste les règles IDS à travers les 5 niveaux de sécurité:
-- - Niveau 1: Règles minimales (facile à évader)
-- - Niveau 2: Règles basiques
-- - Niveau 3: Règles intermédiaires
-- - Niveau 4: Règles avancées
-- - Niveau 5: Règles paranoid (difficile à évader)
--
-- USAGE:
--   lua5.3 scan_all_levels.lua [IDS] [TARGET_IP]
--
-- ARGUMENTS:
--   IDS        Le lab à tester: snort, suricata, zeek (défaut: suricata)
--   TARGET_IP  IP de la cible (auto-détecté si non spécifié)
--
-- OPTIONS:
--   --auto       Ne pas attendre entre les niveaux
--   -h, --help   Afficher cette aide
-- =============================================================================

package.path = package.path .. ";./lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local IDS_CONFIG = {
    snort = {
        target = "target_snort",
        rules_dir = "snort-lab/config",
        rules_file = "local.rules",
        reload_cmd = "docker kill -s SIGHUP snort_ids",
        template_dir = "commander/templates/snort",
    },
    suricata = {
        target = "target_suricata",
        rules_dir = "suricata-lab/rules",
        rules_file = "local.rules",
        reload_cmd = "docker kill -s USR2 suricata_ids",
        template_dir = "commander/templates/suricata",
    },
    zeek = {
        target = "target_zeek",
        rules_dir = "zeek-lab/scripts",
        rules_file = "local.zeek",
        reload_cmd = "docker restart zeek_ids",
        template_dir = "commander/templates/zeek",
    },
}

local OPTIONS = {
    auto = false,
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

local function apply_template(ids_name, level)
    local config = IDS_CONFIG[ids_name]

    -- Trouver le template
    local template_pattern = string.format("%s/%s/level%d*",
        PROJECT_ROOT, config.template_dir, level)

    local find_cmd = string.format("ls %s 2>/dev/null | head -1", template_pattern)
    local template_file, exit_code = T.run(find_cmd)
    template_file = template_file:gsub("%s+", "")

    if exit_code ~= 0 or template_file == "" then
        T.log_warning(string.format("Template niveau %d non trouvé pour %s", level, ids_name))
        return false
    end

    -- Copier le template
    local dest = string.format("%s/%s/%s", PROJECT_ROOT, config.rules_dir, config.rules_file)
    local cp_cmd = string.format("cp '%s' '%s'", template_file, dest)
    T.run(cp_cmd)

    -- Recharger l'IDS
    T.run(config.reload_cmd .. " 2>/dev/null")

    return true
end

local function run_syn_scan(target)
    print("")
    print("📍 Test 1: SYN Scan standard")

    -- Essayer avec sudo
    local cmd = string.format("sudo nmap -sS -p 80 --max-retries 1 -T4 %s 2>/dev/null", target)
    local output, exit_code = T.run(cmd)

    if exit_code ~= 0 then
        -- Fallback TCP connect
        cmd = string.format("nmap -sT -p 80 --max-retries 1 -T4 %s 2>/dev/null", target)
        output, _ = T.run(cmd)
    end

    for line in output:gmatch("[^\n]+") do
        if line:match("open") or line:match("filtered") or line:match("closed") then
            print("   " .. line)
        end
    end
end

local function run_fragment_scan(target)
    print("")
    print("📍 Test 2: Scan avec fragmentation")

    local cmd = string.format("sudo nmap -f -sS -p 80 --max-retries 1 -T4 %s 2>/dev/null", target)
    local output, exit_code = T.run(cmd)

    if exit_code ~= 0 then
        cmd = string.format("nmap -f -sT -p 80 --max-retries 1 -T4 %s 2>/dev/null", target)
        output, _ = T.run(cmd)
    end

    for line in output:gmatch("[^\n]+") do
        if line:match("open") or line:match("filtered") or line:match("closed") then
            print("   " .. line)
        end
    end
end

local function run_slow_scan(target)
    print("")
    print("📍 Test 3: Timing très lent (T1)")

    -- Timeout court car T1 est très lent
    local cmd = string.format("timeout 10 sudo nmap -T1 -sS -p 80 --max-retries 0 %s 2>/dev/null", target)
    local output, _ = T.run(cmd)

    local found = false
    for line in output:gmatch("[^\n]+") do
        if line:match("open") or line:match("filtered") or line:match("closed") then
            print("   " .. line)
            found = true
        end
    end

    if not found then
        print("   Timeout (normal pour T1)")
    end
end

local function wait_for_input()
    if OPTIONS.auto then
        T.sleep(2)
        return
    end

    print("")
    io.write("Appuyez sur Entrée pour passer au niveau suivant...")
    io.flush()
    io.read()
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    local ids_name = "suricata"
    local target = nil

    -- Parse arguments
    for i = 1, #arg do
        if arg[i] == "-h" or arg[i] == "--help" then
            print([[
Usage: lua5.3 scan_all_levels.lua [IDS] [TARGET_IP]

Arguments:
  IDS        Le lab à tester: snort, suricata, zeek (défaut: suricata)
  TARGET_IP  IP de la cible (auto-détecté si non spécifié)

Options:
  --auto       Ne pas attendre entre les niveaux
  -h, --help   Afficher cette aide

Exemple:
  lua5.3 scan_all_levels.lua suricata
  lua5.3 scan_all_levels.lua snort 172.28.0.100 --auto
]])
            os.exit(0)
        elseif arg[i] == "--auto" then
            OPTIONS.auto = true
        elseif not arg[i]:match("^%-") then
            if IDS_CONFIG[arg[i]] then
                ids_name = arg[i]
            else
                target = arg[i]
            end
        end
    end

    local config = IDS_CONFIG[ids_name]
    if not config then
        T.log_error("IDS inconnu: " .. ids_name)
        os.exit(1)
    end

    -- Auto-détecter la cible si non spécifiée
    if not target then
        target = get_container_ip(config.target)
    end

    if not target then
        print("Usage: lua5.3 scan_all_levels.lua <ids> [target_ip]")
        print("  ids: snort, suricata, zeek")
        print("")
        print("Exemple: lua5.3 scan_all_levels.lua suricata")
        os.exit(1)
    end

    -- Header
    print(T.colors.cyan .. T.colors.bold)
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        Test d'évasion IDS - Tous les niveaux                 ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(string.format("║  IDS: %-54s ║", ids_name))
    print(string.format("║  Target: %-51s ║", target))
    print("╚══════════════════════════════════════════════════════════════╝")
    print(T.colors.reset)
    print("")

    -- Tester chaque niveau
    for level = 1, 5 do
        print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)
        print(T.colors.bold .. string.format("🔒 NIVEAU %d", level) .. T.colors.reset)
        print(T.colors.cyan .. "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" .. T.colors.reset)

        -- Appliquer le template
        if not apply_template(ids_name, level) then
            T.log_warning("Impossible d'appliquer le template, utilisation des règles actuelles")
        end

        -- Attendre le rechargement
        T.sleep(2)

        -- Tests
        run_syn_scan(target)
        run_fragment_scan(target)
        run_slow_scan(target)

        if level < 5 then
            wait_for_input()
        end
    end

    print("")
    print(T.colors.green .. "✅ Test terminé." .. T.colors.reset)
    print("")
    print("Consultez les alertes:")
    print("  - EveBox: http://localhost:5636")
    print("  - Kibana: http://localhost:5601")
    print("  - Logs: docker logs " .. ids_name .. "_ids")
end

main()
