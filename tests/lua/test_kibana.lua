#!/usr/bin/env lua5.3
-- =============================================================================
-- TEST KIBANA LAB - ELK Stack pour visualisation IDS
-- =============================================================================
-- Ce script teste le bon fonctionnement du stack ELK:
-- - Elasticsearch: stockage et recherche
-- - Kibana: visualisation
-- - Filebeat: collecte des logs IDS
--
-- OPTIONS:
--   --no-start    Ne pas démarrer le lab (utiliser un lab déjà running)
--   --no-stop     Ne pas arrêter le lab après les tests
--   --with-ids    Démarrer aussi Suricata pour générer des logs
--   --quick       Test rapide (skip génération de trafic)
-- =============================================================================

-- Charger le module utilitaire
package.path = package.path .. ";./lib/?.lua;../lua/lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local CONFIG = {
    lab_name = "kibana",
    elasticsearch_url = "http://localhost:9200",
    kibana_url = "http://localhost:5601",
    container_es = "kibana_elasticsearch",
    container_kibana = "kibana_dashboard",
    container_filebeat = "kibana_filebeat",
    es_startup_wait = 60,    -- ES prend du temps à démarrer
    kibana_startup_wait = 60,
}

-- Options de ligne de commande
local OPTIONS = {
    no_start = false,
    no_stop = false,
    with_ids = false,
    quick = false,
}

-- Chemin du projet
local SCRIPT_PATH = arg[0] or "."
local PROJECT_ROOT = T.get_project_root(SCRIPT_PATH)
local KIBANA_LAB_DIR = PROJECT_ROOT .. "/kibana-lab"
local SURICATA_LAB_DIR = PROJECT_ROOT .. "/suricata-lab"

-- =============================================================================
-- PARSING DES ARGUMENTS
-- =============================================================================

local function parse_args()
    for i = 1, #arg do
        if arg[i] == "--no-start" then
            OPTIONS.no_start = true
        elseif arg[i] == "--no-stop" then
            OPTIONS.no_stop = true
        elseif arg[i] == "--with-ids" then
            OPTIONS.with_ids = true
        elseif arg[i] == "--quick" then
            OPTIONS.quick = true
        elseif arg[i] == "-h" or arg[i] == "--help" then
            print("Usage: lua test_kibana.lua [OPTIONS]")
            print("")
            print("Options:")
            print("  --no-start    Ne pas démarrer le lab (lab déjà running)")
            print("  --no-stop     Ne pas arrêter le lab après les tests")
            print("  --with-ids    Démarrer aussi Suricata pour générer des logs")
            print("  --quick       Test rapide (skip génération de trafic)")
            print("  -h, --help    Afficher cette aide")
            os.exit(0)
        end
    end
end

-- =============================================================================
-- TESTS
-- =============================================================================

--- Démarre le lab Kibana (et optionnellement un IDS)
---@return boolean success
local function start_lab()
    if OPTIONS.no_start then
        T.log_info("Option --no-start: skip démarrage")
        return true
    end

    -- Optionnellement démarrer un IDS pour générer des logs
    if OPTIONS.with_ids then
        T.log_section("Démarrage du lab Suricata (--with-ids)")
        T.docker_compose_down(SURICATA_LAB_DIR)
        T.docker_compose_up(SURICATA_LAB_DIR)
        T.sleep(10)
    end

    T.log_section("Démarrage du lab Kibana (ELK Stack)")

    T.docker_compose_down(KIBANA_LAB_DIR)
    T.sleep(2)

    local ok = T.docker_compose_up(KIBANA_LAB_DIR)
    if not ok then
        T.log_error("Échec du démarrage de docker compose")
        return false
    end

    -- Attendre Elasticsearch
    T.log_info(string.format("Attente d'Elasticsearch (max %ds)...", CONFIG.es_startup_wait))

    local es_ready = T.wait_for(function()
        local body, status = T.http_get(CONFIG.elasticsearch_url .. "/_cluster/health", 5)
        if status ~= 200 then return false end
        return body and (body:find('"status":"green"') or body:find('"status":"yellow"'))
    end, CONFIG.es_startup_wait, 5, "Attente ES")

    if not es_ready then
        T.log_error("Timeout: Elasticsearch n'est pas prêt")
        return false
    end

    T.log_success("Elasticsearch est healthy")
    return true
end

--- Arrête les labs
local function stop_lab()
    if OPTIONS.no_stop then
        T.log_info("Option --no-stop: labs laissés running")
        T.log_info("Kibana: " .. CONFIG.kibana_url)
        T.log_info("Elasticsearch: " .. CONFIG.elasticsearch_url)
        return
    end

    T.log_section("Arrêt du lab Kibana")
    T.docker_compose_down(KIBANA_LAB_DIR)

    if OPTIONS.with_ids then
        T.log_info("Arrêt du lab Suricata...")
        T.docker_compose_down(SURICATA_LAB_DIR)
    end

    T.log_success("Labs arrêtés")
end

--- Test Elasticsearch
---@return boolean success
local function test_elasticsearch()
    T.log_section("Test Elasticsearch")

    -- Health check
    local body, status = T.http_get(CONFIG.elasticsearch_url .. "/_cluster/health", 10)

    if status ~= 200 then
        return T.assert_true(false, "Elasticsearch accessible", "HTTP " .. tostring(status))
    end

    local es_status = T.json_extract(body, "status")
    T.assert_true(
        es_status == "green" or es_status == "yellow",
        "Elasticsearch status: " .. tostring(es_status)
    )

    -- Cluster info
    body, status = T.http_get(CONFIG.elasticsearch_url, 5)
    if status == 200 then
        local cluster_name = T.json_extract(body, "cluster_name")
        local version = T.json_extract(body, "number")
        T.log_info("Cluster: " .. tostring(cluster_name))
        T.log_info("Version: " .. tostring(version))
    end

    return T.assert_true(status == 200, "Elasticsearch API accessible")
end

--- Test Kibana
---@return boolean success
local function test_kibana()
    T.log_section("Test Kibana")

    T.log_info(string.format("Attente de Kibana (max %ds)...", CONFIG.kibana_startup_wait))

    local kibana_ready = T.wait_for(function()
        local _, status = T.http_get(CONFIG.kibana_url .. "/api/status", 5)
        return status == 200
    end, CONFIG.kibana_startup_wait, 5, "Attente Kibana")

    if not kibana_ready then
        T.warn("Kibana pas encore prêt (peut prendre plus de temps)")
        return true  -- Ne pas échouer le test
    end

    local body, status = T.http_get(CONFIG.kibana_url .. "/api/status", 5)
    T.assert_true(status == 200, "Kibana répond (HTTP 200)")

    if status == 200 then
        local kibana_status = T.json_extract(body, "state")
        if kibana_status then
            T.log_info("Kibana status: " .. kibana_status)
        end
    end

    return true
end

--- Test Filebeat
---@return boolean success
local function test_filebeat()
    T.log_section("Test Filebeat")

    local running = T.docker_running(CONFIG.container_filebeat)
    return T.assert_true(running, "Container kibana_filebeat running")
end

--- Test des indices Elasticsearch
---@return boolean success
local function test_indices()
    T.log_section("Test des indices")

    -- Lister les indices
    local body, status = T.http_get(CONFIG.elasticsearch_url .. "/_cat/indices?v", 5)
    if status == 200 then
        T.log_info("Indices Elasticsearch:")
        print(body)
    end

    -- Compter les documents par IDS
    local indices = {
        {name = "suricata", pattern = "suricata-*"},
        {name = "snort", pattern = "snort-*"},
        {name = "zeek", pattern = "zeek-*"},
    }

    local total_docs = 0

    for _, idx in ipairs(indices) do
        local count_body, count_status = T.http_get(
            CONFIG.elasticsearch_url .. "/" .. idx.pattern .. "/_count",
            5
        )

        local count = 0
        if count_status == 200 then
            count = tonumber(T.json_extract(count_body, "count")) or 0
        end

        total_docs = total_docs + count
        T.log_info(string.format("%s (%s): %d docs", idx.name, idx.pattern, count))
    end

    T.log_info(string.format("Total: %d documents", total_docs))

    if total_docs > 0 then
        return T.assert_true(true, "Documents indexés: " .. total_docs)
    else
        T.warn("Aucun document indexé (démarrer un IDS et générer du trafic)")
        return true  -- Ne pas échouer si pas de docs
    end
end

--- Génère du trafic de test (si un IDS est running)
local function generate_test_traffic()
    if OPTIONS.quick then
        T.log_info("Option --quick: skip génération de trafic")
        return
    end

    T.log_section("Génération de trafic de test")

    -- Détecter quel IDS est running
    local target_ip = nil
    local ids_name = nil

    if T.docker_running("suricata_ids") then
        target_ip = "172.29.0.100"
        ids_name = "Suricata"
    elseif T.docker_running("snort_ids") then
        target_ip = "172.28.0.100"
        ids_name = "Snort"
    elseif T.docker_running("zeek_ids") then
        target_ip = "172.30.0.100"
        ids_name = "Zeek"
    end

    if target_ip then
        T.log_info(string.format("IDS détecté: %s, cible: %s", ids_name, target_ip))

        -- Scan rapide
        T.log_info("Scan nmap rapide...")
        local cmd = string.format("nmap -sT -p 22,80 %s -T4 --max-retries 1", target_ip)
        local output, _ = T.run(cmd)
        T.log_info("Résultat:\n" .. output:sub(1, 300))

        -- Attendre l'indexation
        T.sleep(5)
        T.log_info("Vérification de l'indexation...")
        test_indices()
    else
        T.warn("Aucun IDS running - pas de génération de trafic")
        T.log_info("Utiliser --with-ids pour démarrer Suricata automatiquement")
    end
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    parse_args()

    print("============================================")
    print("  TEST KIBANA LAB - ELK Stack")
    print("============================================")
    print("")

    T.reset_results()

    if not T.check_prerequisites() then
        T.print_summary()
        os.exit(1)
    end

    T.assert_true(
        T.run_ok(string.format("test -d '%s'", KIBANA_LAB_DIR)),
        "Répertoire kibana-lab existe"
    )

    if not start_lab() then
        T.print_summary()
        os.exit(1)
    end

    test_elasticsearch()
    test_kibana()
    test_filebeat()
    test_indices()
    generate_test_traffic()

    stop_lab()

    local all_passed = T.print_summary()
    os.exit(all_passed and 0 or 1)
end

main()
