#!/usr/bin/env lua5.3
-- =============================================================================
-- TEST ZEEK LAB - Analyse réseau et métadonnées
-- =============================================================================
-- Ce script teste le bon fonctionnement du lab Zeek:
-- - Démarrage des containers (IDS, target, editor)
-- - Capture et analyse du trafic réseau
-- - Vérification des logs structurés (conn.log, http.log, etc.)
--
-- OPTIONS:
--   --no-start    Ne pas démarrer le lab (utiliser un lab déjà running)
--   --no-stop     Ne pas arrêter le lab après les tests
--   --quick       Test rapide (moins de trafic généré)
-- =============================================================================

-- Charger le module utilitaire
package.path = package.path .. ";./lib/?.lua;../lua/lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local CONFIG = {
    lab_name = "zeek",
    target_ip = "172.30.0.100",
    target_ports = "21,22,80,8080",
    container_ids = "zeek_ids",
    container_target = "target_zeek",
    log_files = {"conn.log", "http.log", "dns.log", "notice.log"},
    startup_wait = 15,
    scan_wait = 3,
}

-- Options de ligne de commande
local OPTIONS = {
    no_start = false,
    no_stop = false,
    quick = false,
}

-- Chemin du projet
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)
local LAB_DIR = PROJECT_ROOT .. "/zeek-lab"
local LOG_DIR = LAB_DIR .. "/logs"

-- =============================================================================
-- PARSING DES ARGUMENTS
-- =============================================================================

local function parse_args()
    for i = 1, #arg do
        if arg[i] == "--no-start" then
            OPTIONS.no_start = true
        elseif arg[i] == "--no-stop" then
            OPTIONS.no_stop = true
        elseif arg[i] == "--quick" then
            OPTIONS.quick = true
        elseif arg[i] == "-h" or arg[i] == "--help" then
            print("Usage: lua test_zeek.lua [OPTIONS]")
            print("")
            print("Options:")
            print("  --no-start    Ne pas démarrer le lab (lab déjà running)")
            print("  --no-stop     Ne pas arrêter le lab après les tests")
            print("  --quick       Test rapide (moins de trafic généré)")
            print("  -h, --help    Afficher cette aide")
            os.exit(0)
        end
    end
end

-- =============================================================================
-- TESTS
-- =============================================================================

--- Démarre le lab Zeek
---@return boolean success
local function start_lab()
    if OPTIONS.no_start then
        T.log_info("Option --no-start: skip démarrage")
        return true
    end

    T.log_section("Démarrage du lab Zeek")

    T.docker_compose_down(LAB_DIR)
    T.sleep(2)

    local ok = T.docker_compose_up(LAB_DIR)
    if not ok then
        T.log_error("Échec du démarrage de docker compose")
        return false
    end

    T.log_info("Attente du démarrage des containers...")

    local ready = T.wait_for(function()
        return T.docker_running(CONFIG.container_ids)
    end, 60, 2, "Attente zeek_ids")

    if not ready then
        T.log_error("Timeout: zeek_ids n'est pas prêt")
        return false
    end

    T.log_success("Lab Zeek démarré")
    T.log_info(string.format("Initialisation de l'IDS (%ds)...", CONFIG.startup_wait))
    T.sleep(CONFIG.startup_wait)

    return true
end

--- Arrête le lab Zeek
local function stop_lab()
    if OPTIONS.no_stop then
        T.log_info("Option --no-stop: lab laissé running")
        T.log_info("Target: " .. CONFIG.target_ip)
        return
    end

    T.log_section("Arrêt du lab Zeek")
    T.docker_compose_down(LAB_DIR)
    T.log_success("Lab Zeek arrêté")
end

--- Vérifie que les containers sont running
---@return boolean success
local function test_containers()
    T.log_section("Vérification des containers")

    local ids_ok = T.assert_true(
        T.docker_running(CONFIG.container_ids),
        "Container zeek_ids running"
    )

    local target_ok = T.assert_true(
        T.docker_running(CONFIG.container_target),
        "Container target_zeek running"
    )

    return ids_ok and target_ok
end

--- Lance des scans et du trafic pour générer des logs
local function run_traffic_generation()
    T.log_section("Génération de trafic")

    local target = CONFIG.target_ip
    local ports = CONFIG.target_ports

    -- Scan TCP Connect
    T.log_info("Scan TCP Connect (-sT)...")
    local cmd = string.format("nmap -sT -p %s %s -T4 --max-retries 1", ports, target)
    local output, _ = T.run(cmd)
    T.log_info("Résultat:\n" .. output:sub(1, 500))
    T.sleep(CONFIG.scan_wait)

    -- Requête HTTP
    T.log_info("Requête HTTP vers le target...")
    cmd = string.format("curl -s -o /dev/null -w '%%{http_code}' 'http://%s/' --connect-timeout 5", target)
    local http_code, _ = T.run(cmd)
    T.log_info("HTTP response: " .. http_code:gsub("%s+", ""))
    T.sleep(CONFIG.scan_wait)

    -- Scan Version
    T.log_info("Scan Version Detection (-sV)...")
    cmd = string.format("nmap -sV -p 22,80 %s -T4 --max-retries 1", target)
    T.run(cmd)
    T.sleep(CONFIG.scan_wait)

    T.log_success("Trafic généré")
end

--- Compte les lignes dans un log Zeek (excluant les headers #)
---@param filename string Nom du fichier log
---@return number count Nombre de lignes de données
local function count_zeek_log_entries(filename)
    local filepath = LOG_DIR .. "/" .. filename
    local cmd = string.format("grep -v '^#' '%s' 2>/dev/null | wc -l", filepath)
    local output, _ = T.run(cmd)
    return tonumber(output:match("%d+")) or 0
end

--- Vérifie les logs Zeek
---@return boolean success
local function test_logs()
    T.log_section("Vérification des logs Zeek")

    T.sleep(3)  -- Attendre que Zeek écrive les logs

    local total_entries = 0
    local logs_with_data = 0

    for _, logfile in ipairs(CONFIG.log_files) do
        local count = count_zeek_log_entries(logfile)
        total_entries = total_entries + count

        if count > 0 then
            T.log_success(string.format("%s: %d entrées", logfile, count))
            logs_with_data = logs_with_data + 1
        else
            T.log_info(string.format("%s: 0 entrées", logfile))
        end
    end

    -- Afficher un échantillon de conn.log
    T.log_info("Échantillon conn.log:")
    local sample_cmd = string.format("grep -v '^#' '%s/conn.log' 2>/dev/null | tail -5", LOG_DIR)
    local sample, _ = T.run(sample_cmd)
    if sample ~= "" then
        print(sample)
    else
        T.log_info("(conn.log vide ou non accessible)")
    end

    -- Test passé si on a au moins des entrées dans conn.log
    return T.assert_greater(total_entries, 0, "Logs Zeek générés")
end

--- Vérifie les notices (alertes) Zeek
local function test_notices()
    T.log_section("Vérification des notices Zeek")

    local notice_count = count_zeek_log_entries("notice.log")

    if notice_count > 0 then
        T.log_success(string.format("Notices détectées: %d", notice_count))

        -- Afficher les notices
        T.log_info("Contenu notice.log:")
        local cmd = string.format("grep -v '^#' '%s/notice.log' 2>/dev/null", LOG_DIR)
        local notices, _ = T.run(cmd)
        print(notices)
    else
        T.log_info("Aucune notice (normal si pas de comportement suspect détecté)")
    end

    return true  -- Les notices sont optionnelles
end

--- Test de l'API Commander (optionnel)
local function test_api()
    T.log_section("Test API Commander (optionnel)")

    local body, status = T.http_get("http://localhost:3000/api/alerts/zeek", 5)

    if status ~= 200 then
        T.warn("API Commander non accessible")
        return true
    end

    local count = T.json_extract(body, "count")
    if count then
        T.log_success(string.format("API: %s entrées", count))
    else
        T.warn("Pas de données via API")
    end

    return true
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    parse_args()

    print("============================================")
    print("  TEST ZEEK LAB - Analyse réseau")
    print("============================================")
    print("")

    T.reset_results()

    if not T.check_prerequisites() then
        T.print_summary()
        os.exit(1)
    end

    T.assert_true(T.run_ok("nmap --version"), "nmap installé")
    T.assert_true(T.run_ok(string.format("test -d '%s'", LAB_DIR)), "Répertoire zeek-lab existe")

    if not start_lab() then
        T.print_summary()
        os.exit(1)
    end

    local success = true

    success = test_containers() and success
    run_traffic_generation()
    success = test_logs() and success
    test_notices()
    test_api()

    stop_lab()

    local all_passed = T.print_summary()
    os.exit(all_passed and 0 or 1)
end

main()
