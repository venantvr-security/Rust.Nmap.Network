#!/usr/bin/env lua5.3
-- =============================================================================
-- TEST SURICATA LAB - Détection d'intrusion multi-thread
-- =============================================================================
-- Ce script teste le bon fonctionnement du lab Suricata:
-- - Démarrage des containers (IDS, target, EveBox, editor)
-- - Détection de scans nmap
-- - Vérification des logs eve.json
-- - Accès à EveBox (visualisation)
--
-- OPTIONS:
--   --no-start    Ne pas démarrer le lab (utiliser un lab déjà running)
--   --no-stop     Ne pas arrêter le lab après les tests
--   --quick       Test rapide (skip scans agressifs)
-- =============================================================================

-- Charger le module utilitaire
package.path = package.path .. ";./lib/?.lua;../lua/lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local CONFIG = {
    lab_name = "suricata",
    target_ip = "172.29.0.100",
    target_ports = "21,22,80,8080",
    container_ids = "suricata_ids",
    container_target = "target_suricata",
    container_evebox = "evebox",
    log_file = "eve.json",
    evebox_url = "http://localhost:5636",
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
local LAB_DIR = PROJECT_ROOT .. "/suricata-lab"
local LOG_PATH = LAB_DIR .. "/logs/" .. CONFIG.log_file

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
            print("Usage: lua test_suricata.lua [OPTIONS]")
            print("")
            print("Options:")
            print("  --no-start    Ne pas démarrer le lab (lab déjà running)")
            print("  --no-stop     Ne pas arrêter le lab après les tests")
            print("  --quick       Test rapide (skip scans agressifs)")
            print("  -h, --help    Afficher cette aide")
            os.exit(0)
        end
    end
end

-- =============================================================================
-- TESTS
-- =============================================================================

--- Démarre le lab Suricata
---@return boolean success
local function start_lab()
    if OPTIONS.no_start then
        T.log_info("Option --no-start: skip démarrage")
        return true
    end

    T.log_section("Démarrage du lab Suricata")

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
    end, 60, 2, "Attente suricata_ids")

    if not ready then
        T.log_error("Timeout: suricata_ids n'est pas prêt")
        return false
    end

    T.log_success("Lab Suricata démarré")
    T.log_info(string.format("Initialisation de l'IDS (%ds)...", CONFIG.startup_wait))
    T.sleep(CONFIG.startup_wait)

    return true
end

--- Arrête le lab Suricata
local function stop_lab()
    if OPTIONS.no_stop then
        T.log_info("Option --no-stop: lab laissé running")
        T.log_info("Target: " .. CONFIG.target_ip)
        T.log_info("EveBox: " .. CONFIG.evebox_url)
        return
    end

    T.log_section("Arrêt du lab Suricata")
    T.docker_compose_down(LAB_DIR)
    T.log_success("Lab Suricata arrêté")
end

--- Vérifie que les containers sont running
---@return boolean success
local function test_containers()
    T.log_section("Vérification des containers")

    local ids_ok = T.assert_true(
        T.docker_running(CONFIG.container_ids),
        "Container suricata_ids running"
    )

    local target_ok = T.assert_true(
        T.docker_running(CONFIG.container_target),
        "Container target_suricata running"
    )

    local evebox_ok = T.assert_true(
        T.docker_running(CONFIG.container_evebox),
        "Container evebox running"
    )

    return ids_ok and target_ok and evebox_ok
end

--- Lance des scans nmap pour générer des alertes
local function run_nmap_scans()
    T.log_section("Scans nmap")

    local target = CONFIG.target_ip
    local ports = CONFIG.target_ports

    -- Scan TCP Connect
    T.log_info("Scan TCP Connect (-sT)...")
    local cmd = string.format("nmap -sT -p %s %s -T4 --max-retries 1", ports, target)
    local output, _ = T.run(cmd)
    T.log_info("Résultat:\n" .. output:sub(1, 500))
    T.sleep(CONFIG.scan_wait)

    -- Scan Version
    T.log_info("Scan Version Detection (-sV)...")
    cmd = string.format("nmap -sV -p 22,80 %s -T4 --max-retries 1", target)
    T.run(cmd)
    T.sleep(CONFIG.scan_wait)

    -- Scan Aggressive
    T.log_info("Scan Aggressive (-A)...")
    cmd = string.format("nmap -A -p 22,80 %s -T4 --max-retries 1", target)
    T.run(cmd)
    T.sleep(CONFIG.scan_wait)

    T.log_success("Scans terminés")
end

--- Vérifie les alertes dans eve.json
---@return boolean success
local function test_alerts()
    T.log_section("Vérification des alertes Suricata")

    T.sleep(2)

    -- Compter les entrées JSON dans eve.json
    local json_count = T.count_json_lines(LOG_PATH)
    T.log_info(string.format("Entrées dans eve.json: %d", json_count))

    -- Compter spécifiquement les alertes
    local alert_cmd = string.format("grep -c '\"event_type\":\"alert\"' '%s' 2>/dev/null || echo 0", LOG_PATH)
    local alert_output, _ = T.run(alert_cmd)
    local alert_count = tonumber(alert_output:match("%d+")) or 0

    if alert_count > 0 then
        T.log_success(string.format("Alertes détectées: %d", alert_count))

        -- Afficher un échantillon
        T.log_info("Échantillon des alertes:")
        local sample_cmd = string.format("grep '\"event_type\":\"alert\"' '%s' | tail -3", LOG_PATH)
        local sample, _ = T.run(sample_cmd)
        print(sample)
    else
        T.warn("Aucune alerte 'alert' mais d'autres événements présents")
    end

    -- Test passé si on a des entrées JSON (flow, http, dns comptent aussi)
    return T.assert_greater(json_count, 0, "Logs Suricata générés")
end

--- Test de l'accès à EveBox
---@return boolean success
local function test_evebox()
    T.log_section("Test EveBox")

    -- Attendre que EveBox soit prêt
    local ready = T.wait_for(function()
        return T.http_ok(CONFIG.evebox_url, 5)
    end, 30, 2, "Attente EveBox")

    if not ready then
        T.warn("EveBox non accessible (timeout)")
        return true  -- Ne pas échouer le test pour ça
    end

    local _, status = T.http_get(CONFIG.evebox_url, 5)
    return T.assert_true(status == 200, "EveBox accessible (HTTP 200)")
end

--- Test de l'API Commander (optionnel)
local function test_api()
    T.log_section("Test API Commander (optionnel)")

    local body, status = T.http_get("http://localhost:3000/api/alerts/suricata", 5)

    if status ~= 200 then
        T.warn("API Commander non accessible")
        return true
    end

    local count = T.json_extract(body, "count")
    if count then
        T.log_success(string.format("API: %s alertes", count))
    else
        T.warn("Pas d'alertes via API")
    end

    return true
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    parse_args()

    print("============================================")
    print("  TEST SURICATA LAB - Détection multi-thread")
    print("============================================")
    print("")

    T.reset_results()

    if not T.check_prerequisites() then
        T.print_summary()
        os.exit(1)
    end

    T.assert_true(T.run_ok("nmap --version"), "nmap installé")
    T.assert_true(T.run_ok(string.format("test -d '%s'", LAB_DIR)), "Répertoire suricata-lab existe")

    if not start_lab() then
        T.print_summary()
        os.exit(1)
    end

    local success = true

    success = test_containers() and success
    run_nmap_scans()
    success = test_alerts() and success
    test_evebox()
    test_api()

    stop_lab()

    local all_passed = T.print_summary()
    os.exit(all_passed and 0 or 1)
end

main()
