#!/usr/bin/env lua5.3
-- =============================================================================
-- TEST RUNNER - Exécute tous les tests IDS Labs
-- =============================================================================
-- Ce script lance les tests pour chaque lab:
-- - Snort Lab (détection par signatures)
-- - Suricata Lab (détection multi-thread)
-- - Zeek Lab (analyse réseau)
-- - Kibana Lab (ELK Stack)
--
-- USAGE:
--   lua run_all.lua              # Tous les tests
--   lua run_all.lua snort        # Un seul test
--   lua run_all.lua --list       # Lister les tests disponibles
--   lua run_all.lua --help       # Aide
--
-- OPTIONS:
--   --no-stop     Ne pas arrêter les labs après les tests
--   --quick       Tests rapides (skip génération de trafic)
-- =============================================================================

-- Charger le module utilitaire
package.path = package.path .. ";./lib/?.lua"
local T = require("test_utils")

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

local TESTS = {
    {name = "snort",    script = "test_snort.lua",    desc = "Snort Lab - Détection par signatures"},
    {name = "suricata", script = "test_suricata.lua", desc = "Suricata Lab - Détection multi-thread"},
    {name = "zeek",     script = "test_zeek.lua",     desc = "Zeek Lab - Analyse réseau"},
    {name = "kibana",   script = "test_kibana.lua",   desc = "Kibana Lab - ELK Stack"},
}

local OPTIONS = {
    no_stop = false,
    quick = false,
}

-- Chemin du script
local SCRIPT_DIR = arg[0]:match("(.*/)")  or "./"

-- =============================================================================
-- FONCTIONS
-- =============================================================================

local function show_help()
    print([[
Usage: lua run_all.lua [OPTIONS] [TEST...]

Arguments:
  TEST          Nom(s) du test à exécuter (snort, suricata, zeek, kibana)
                Sans argument, exécute tous les tests

Options:
  --list        Lister les tests disponibles
  --no-stop     Ne pas arrêter les labs après les tests
  --quick       Tests rapides (skip génération de trafic)
  -h, --help    Afficher cette aide

Exemples:
  lua run_all.lua                    # Tous les tests
  lua run_all.lua snort suricata     # Snort et Suricata uniquement
  lua run_all.lua kibana --no-stop   # Kibana, laisser running
  lua run_all.lua --quick            # Tests rapides
]])
end

local function list_tests()
    print("Tests disponibles:")
    print("")
    for _, test in ipairs(TESTS) do
        print(string.format("  %-12s %s", test.name, test.desc))
    end
    print("")
end

local function find_test(name)
    for _, test in ipairs(TESTS) do
        if test.name == name then
            return test
        end
    end
    return nil
end

local function run_test(test)
    print("")
    print(string.rep("=", 60))
    print(string.format("  RUNNING: %s", test.desc))
    print(string.rep("=", 60))
    print("")

    local script_path = SCRIPT_DIR .. test.script

    -- Construire les arguments
    local extra_args = ""
    if OPTIONS.no_stop then
        extra_args = extra_args .. " --no-stop"
    end
    if OPTIONS.quick then
        extra_args = extra_args .. " --quick"
    end

    -- Exécuter le test
    local cmd = string.format("lua '%s'%s", script_path, extra_args)
    local _, exit_code = T.run(cmd)

    -- Afficher le résultat (le script affiche déjà son propre résumé via stdout)
    -- On capture juste le code de sortie

    return exit_code == 0
end

-- =============================================================================
-- MAIN
-- =============================================================================

local function main()
    local tests_to_run = {}

    -- Parser les arguments
    local i = 1
    while i <= #arg do
        local a = arg[i]

        if a == "-h" or a == "--help" then
            show_help()
            os.exit(0)
        elseif a == "--list" then
            list_tests()
            os.exit(0)
        elseif a == "--no-stop" then
            OPTIONS.no_stop = true
        elseif a == "--quick" then
            OPTIONS.quick = true
        elseif a:sub(1, 1) ~= "-" then
            -- C'est un nom de test
            local test = find_test(a)
            if test then
                table.insert(tests_to_run, test)
            else
                print(T.colors.red .. "Erreur: test inconnu: " .. a .. T.colors.reset)
                print("Utilisez --list pour voir les tests disponibles")
                os.exit(1)
            end
        end
        i = i + 1
    end

    -- Si aucun test spécifié, tous les exécuter
    if #tests_to_run == 0 then
        tests_to_run = TESTS
    end

    -- Header
    print("")
    print(T.colors.cyan .. T.colors.bold)
    print("╔══════════════════════════════════════════════════════════╗")
    print("║           IDS LAB - TEST SUITE (Lua)                     ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(T.colors.reset)

    print(string.format("Tests à exécuter: %d", #tests_to_run))
    for _, test in ipairs(tests_to_run) do
        print(string.format("  • %s", test.name))
    end

    -- Exécuter les tests
    local results = {}
    local start_time = os.time()

    for _, test in ipairs(tests_to_run) do
        local success = run_test(test)
        table.insert(results, {test = test, success = success})
    end

    local elapsed = os.time() - start_time

    -- Résumé final
    print("")
    print(T.colors.cyan .. T.colors.bold)
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                   RÉSUMÉ FINAL                           ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(T.colors.reset)

    local passed = 0
    local failed = 0

    for _, r in ipairs(results) do
        if r.success then
            print(string.format("  %s✓ %s%s", T.colors.green, r.test.name, T.colors.reset))
            passed = passed + 1
        else
            print(string.format("  %s✗ %s%s", T.colors.red, r.test.name, T.colors.reset))
            failed = failed + 1
        end
    end

    print("")
    print(string.format("  Temps total: %d secondes", elapsed))
    print(string.format("  Passés: %s%d%s", T.colors.green, passed, T.colors.reset))

    if failed > 0 then
        print(string.format("  Échoués: %s%d%s", T.colors.red, failed, T.colors.reset))
    end

    print("")

    os.exit(failed > 0 and 1 or 0)
end

main()
