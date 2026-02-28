#!/usr/bin/env lua5.3
-- =============================================================================
-- TEST SNORT LAB - Détection d'intrusion par signatures
-- =============================================================================
-- Ce script teste le bon fonctionnement du lab Snort:
-- - Démarrage des containers (IDS, target, editor)
-- - Détection de scans nmap
-- - Vérification des logs d'alertes
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
    lab_name = "snort",
    target_ip = "172.28.0.100",
    target_ports = "21,22,80,8080",
    container_ids = "snort_ids",
    container_target = "target_snort",
    log_file = "alert_fast.txt",
    startup_wait = 15,
    scan_wait = 3,
}

-- Options de ligne de commande
local OPTIONS = {
    no_start = false,
    no_stop = false,
    quick = false,
}

-- Chemin du projet (résolu depuis le script)
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)
local LAB_DIR = PROJECT_ROOT .. "/snort-lab"
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
            print("Usage: lua test_snort.lua [OPTIONS]")
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

--- Démarre le lab Snort
---@return boolean success
local function start_lab()
    if OPTIONS.no_start then
        T.log_info("Option --no-start: skip démarrage")
        return true
    end

    T.log_section("Démarrage du lab Snort")

    -- Arrêter d'abord si running
    T.docker_compose_down(LAB_DIR)
    T.sleep(2)

    -- Démarrer le lab
    local ok = T.docker_compose_up(LAB_DIR)
    if not ok then
        T.log_error("Échec du démarrage de docker compose")
        return false
    end

    -- Attendre que les containers soient prêts
    T.log_info("Attente du démarrage des containers...")

    local ready = T.wait_for(function()
        return T.docker_running(CONFIG.container_ids)
    end, 60, 2, "Attente snort_ids")

    if not ready then
        T.log_error("Timeout: snort_ids n'est pas prêt")
        return false
    end

    T.log_success("Lab Snort démarré")

    -- Attendre l'initialisation de l'IDS
    T.log_info(string.format("Initialisation de l'IDS (%ds)...", CONFIG.startup_wait))
    T.sleep(CONFIG.startup_wait)

    return true
end

--- Arrête le lab Snort
local function stop_lab()
    if OPTIONS.no_stop then
        T.log_info("Option --no-stop: lab laissé running")
        T.log_info("Target: " .. CONFIG.target_ip)
        return
    end

    T.log_section("Arrêt du lab Snort")
    T.docker_compose_down(LAB_DIR)
    T.log_success("Lab Snort arrêté")
end

--- Vérifie que les containers sont running
---@return boolean success
local function test_containers()
    T.log_section("Vérification des containers")

    local ids_ok = T.assert_true(
        T.docker_running(CONFIG.container_ids),
        "Container snort_ids running"
    )

    local target_ok = T.assert_true(
        T.docker_running(CONFIG.container_target),
        "Container target_snort running"
    )

    return ids_ok and target_ok
end

--- Lance des scans nmap pour générer des alertes
local function run_nmap_scans()
    T.log_section("Scans nmap")

    local target = CONFIG.target_ip
    local ports = CONFIG.target_ports

    -- Scan TCP Connect (ne nécessite pas sudo)
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

    -- Scan Aggressive (si possible)
    T.log_info("Scan Aggressive (-A)...")
    cmd = string.format("nmap -A -p 22,80 %s -T4 --max-retries 1", target)
    T.run(cmd)
    T.sleep(CONFIG.scan_wait)

    T.log_success("Scans terminés")
end

--- Vérifie les alertes Snort
---@return boolean success
local function test_alerts()
    T.log_section("Vérification des alertes Snort")

    -- Attendre un peu pour que les logs soient écrits
    T.sleep(2)

    -- Méthode 1: Lire le fichier de logs directement
    local alert_count = T.count_lines(LOG_PATH)

    if alert_count > 0 then
        T.log_success(string.format("Fichier alert_fast.txt: %d lignes", alert_count))

        -- Afficher un échantillon des alertes
        T.log_info("Échantillon des alertes:")
        local sample, _ = T.run(string.format("tail -5 '%s' 2>/dev/null", LOG_PATH))
        print(sample)
    else
        -- Méthode 2: Lire via docker exec
        T.log_info("Lecture via docker exec...")
        local output, ok = T.docker_run(CONFIG.container_ids, "cat /var/log/snort/alert_fast.txt")
        if ok then
            alert_count = 0
            for _ in output:gmatch("[^\n]+") do
                alert_count = alert_count + 1
            end
            if alert_count > 0 then
                T.log_success(string.format("Docker exec: %d alertes", alert_count))
                T.log_info("Échantillon:")
                print(output:sub(1, 1000))
            end
        end
    end

    return T.assert_greater(alert_count, 0, "Alertes Snort détectées")
end

--- Test de l'API Commander (optionnel)
local function test_api()
    T.log_section("Test API Commander (optionnel)")

    local body, status = T.http_get("http://localhost:3000/api/alerts/snort", 5)

    if status ~= 200 then
        T.warn("API Commander non accessible (normal si non démarré)")
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
    print("  TEST SNORT LAB - Détection par signatures")
    print("============================================")
    print("")

    T.reset_results()

    -- Prérequis
    if not T.check_prerequisites() then
        T.print_summary()
        os.exit(1)
    end

    -- Vérifier nmap
    T.assert_true(T.run_ok("nmap --version"), "nmap installé")

    -- Vérifier le répertoire du lab
    T.assert_true(
        T.run_ok(string.format("test -d '%s'", LAB_DIR)),
        "Répertoire snort-lab existe"
    )

    -- Démarrer le lab
    if not start_lab() then
        T.print_summary()
        os.exit(1)
    end

    -- Exécuter les tests
    local success = true

    success = test_containers() and success
    run_nmap_scans()
    success = test_alerts() and success
    test_api()

    -- Arrêter le lab
    stop_lab()

    -- Résumé
    local all_passed = T.print_summary()

    os.exit(all_passed and 0 or 1)
end

main()
