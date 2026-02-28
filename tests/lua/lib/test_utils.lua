-- =============================================================================
-- TEST UTILITIES - Framework de test Lua pour IDS Labs
-- =============================================================================
-- Module utilitaire fournissant:
-- - Logging coloré (PASS/FAIL/INFO/WARN)
-- - Requêtes HTTP (via curl)
-- - Commandes Docker
-- - Parsing JSON
-- - Assertions de test
-- =============================================================================

local M = {}

-- =============================================================================
-- COULEURS ANSI
-- =============================================================================
M.colors = {
    red = "\27[0;31m",
    green = "\27[0;32m",
    yellow = "\27[1;33m",
    blue = "\27[0;34m",
    magenta = "\27[0;35m",
    cyan = "\27[0;36m",
    reset = "\27[0m",
    bold = "\27[1m"
}

-- =============================================================================
-- LOGGING
-- =============================================================================

--- Log un message d'information
---@param msg string Message à afficher
function M.log_info(msg)
    print(M.colors.blue .. "[INFO]" .. M.colors.reset .. " " .. msg)
end

--- Log un message de succès
---@param msg string Message à afficher
function M.log_success(msg)
    print(M.colors.green .. "[PASS]" .. M.colors.reset .. " " .. msg)
end

--- Log un message d'erreur
---@param msg string Message à afficher
function M.log_error(msg)
    print(M.colors.red .. "[FAIL]" .. M.colors.reset .. " " .. msg)
end

--- Log un message d'avertissement
---@param msg string Message à afficher
function M.log_warning(msg)
    print(M.colors.yellow .. "[WARN]" .. M.colors.reset .. " " .. msg)
end

--- Log un titre de section
---@param title string Titre de la section
function M.log_section(title)
    print("")
    print(M.colors.cyan .. M.colors.bold .. "=== " .. title .. " ===" .. M.colors.reset)
end

-- =============================================================================
-- EXÉCUTION DE COMMANDES
-- =============================================================================

--- Exécute une commande shell et retourne stdout et le code de retour
--- Note: Utilise io.popen pour capturer la sortie de manière sécurisée
---@param cmd string Commande à exécuter
---@return string stdout Sortie standard
---@return number exit_code Code de retour
function M.run(cmd)
    local handle = io.popen(cmd .. " 2>&1")
    if not handle then
        return "", 1
    end

    local stdout = handle:read("*a")
    local success, _, code = handle:close()

    -- Lua 5.1 vs 5.2+ compatibility
    local exit_code = 0
    if type(success) == "boolean" then
        exit_code = success and 0 or 1
    elseif code then
        exit_code = code
    end

    return stdout or "", exit_code
end

--- Exécute une commande et retourne true si succès
---@param cmd string Commande à exécuter
---@return boolean success True si la commande a réussi
function M.run_ok(cmd)
    local _, exit_code = M.run(cmd)
    return exit_code == 0
end

-- =============================================================================
-- HTTP (via curl)
-- =============================================================================

--- Effectue une requête HTTP GET
---@param url string URL à requêter
---@param timeout number? Timeout en secondes (défaut: 10)
---@return string|nil body Corps de la réponse ou nil si erreur
---@return number status_code Code HTTP (0 si erreur)
function M.http_get(url, timeout)
    timeout = timeout or 10
    local cmd = string.format(
        'curl -s -w "\\n%%{http_code}" --connect-timeout %d "%s"',
        timeout, url
    )

    local output, exit_code = M.run(cmd)

    if exit_code ~= 0 then
        return nil, 0
    end

    -- Séparer le body du status code
    local lines = {}
    for line in output:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    local status_code = tonumber(table.remove(lines)) or 0
    local body = table.concat(lines, "\n")

    return body, status_code
end

--- Vérifie si une URL est accessible
---@param url string URL à vérifier
---@param timeout number? Timeout en secondes
---@return boolean accessible True si accessible (HTTP 200-399)
function M.http_ok(url, timeout)
    local _, status = M.http_get(url, timeout)
    return status >= 200 and status < 400
end

-- =============================================================================
-- JSON (extraction simple)
-- =============================================================================

--- Extrait une valeur d'un JSON par clé (recherche simple par pattern)
---@param json_str string Chaîne JSON
---@param key string Clé à rechercher
---@return string|nil value Valeur trouvée
function M.json_extract(json_str, key)
    if not json_str then return nil end

    -- Pattern pour "key":"value" ou "key":value
    local pattern = '"' .. key .. '"%s*:%s*"?([^",}%]]+)"?'
    local value = json_str:match(pattern)
    return value
end

--- Compte les occurrences d'un pattern dans un JSON
---@param json_str string Chaîne JSON
---@param pattern string Pattern à compter
---@return number count Nombre d'occurrences
function M.json_count(json_str, pattern)
    if not json_str then return 0 end
    local count = 0
    for _ in json_str:gmatch(pattern) do
        count = count + 1
    end
    return count
end

-- =============================================================================
-- DOCKER
-- =============================================================================

--- Vérifie si un container Docker est running
---@param name_pattern string Pattern du nom du container
---@return boolean running True si au moins un container match et est running
function M.docker_running(name_pattern)
    local output, exit_code = M.run("docker ps --format '{{.Names}}'")

    if exit_code ~= 0 then return false end

    for line in output:gmatch("[^\r\n]+") do
        if line:find(name_pattern, 1, true) then
            return true
        end
    end
    return false
end

--- Démarre un lab Docker Compose
---@param lab_dir string Répertoire du lab
---@return boolean success True si démarré avec succès
function M.docker_compose_up(lab_dir)
    local cmd = string.format(
        "cd '%s' && docker compose up -d",
        lab_dir
    )
    local _, exit_code = M.run(cmd)
    return exit_code == 0
end

--- Arrête un lab Docker Compose
---@param lab_dir string Répertoire du lab
---@return boolean success True si arrêté avec succès
function M.docker_compose_down(lab_dir)
    local cmd = string.format(
        "cd '%s' && docker compose down --remove-orphans",
        lab_dir
    )
    local _, exit_code = M.run(cmd)
    return exit_code == 0
end

--- Exécute une commande dans un container
---@param container string Nom du container
---@param cmd string Commande à exécuter
---@return string output Sortie de la commande
---@return boolean success True si succès
function M.docker_run(container, cmd)
    local full_cmd = string.format("docker exec %s %s", container, cmd)
    local output, exit_code = M.run(full_cmd)
    return output, exit_code == 0
end

-- =============================================================================
-- ASSERTIONS
-- =============================================================================

local test_results = {
    passed = 0,
    failed = 0,
    warnings = 0
}

--- Réinitialise les compteurs de test
function M.reset_results()
    test_results.passed = 0
    test_results.failed = 0
    test_results.warnings = 0
end

--- Assert qu'une condition est vraie
---@param condition boolean Condition à vérifier
---@param success_msg string Message en cas de succès
---@param failure_msg string? Message en cas d'échec
---@return boolean passed True si la condition est vraie
function M.assert_true(condition, success_msg, failure_msg)
    if condition then
        M.log_success(success_msg)
        test_results.passed = test_results.passed + 1
        return true
    else
        M.log_error(failure_msg or ("NOT: " .. success_msg))
        test_results.failed = test_results.failed + 1
        return false
    end
end

--- Assert qu'une valeur n'est pas nil
---@param value any Valeur à vérifier
---@param msg string Message descriptif
---@return boolean passed True si la valeur n'est pas nil
function M.assert_not_nil(value, msg)
    return M.assert_true(value ~= nil, msg, msg .. " (got nil)")
end

--- Assert qu'une valeur est égale à une autre
---@param actual any Valeur actuelle
---@param expected any Valeur attendue
---@param msg string Message descriptif
---@return boolean passed True si les valeurs sont égales
function M.assert_equals(actual, expected, msg)
    return M.assert_true(
        actual == expected,
        msg .. " = " .. tostring(expected),
        msg .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual)
    )
end

--- Assert qu'une chaîne contient un pattern
---@param str string Chaîne à vérifier
---@param pattern string Pattern à chercher
---@param msg string Message descriptif
---@return boolean passed True si le pattern est trouvé
function M.assert_contains(str, pattern, msg)
    local found = str and str:find(pattern, 1, true) ~= nil
    return M.assert_true(found, msg, msg .. " (pattern not found: " .. pattern .. ")")
end

--- Assert qu'un nombre est supérieur à un autre
---@param actual number Valeur actuelle
---@param expected number Valeur minimale attendue
---@param msg string Message descriptif
---@return boolean passed True si actual > expected
function M.assert_greater(actual, expected, msg)
    return M.assert_true(
        actual > expected,
        msg .. " (" .. tostring(actual) .. " > " .. tostring(expected) .. ")",
        msg .. ": " .. tostring(actual) .. " <= " .. tostring(expected)
    )
end

--- Log un avertissement (compte comme warning, pas failure)
---@param msg string Message d'avertissement
function M.warn(msg)
    M.log_warning(msg)
    test_results.warnings = test_results.warnings + 1
end

--- Retourne les résultats des tests
---@return table results {passed, failed, warnings}
function M.get_results()
    return {
        passed = test_results.passed,
        failed = test_results.failed,
        warnings = test_results.warnings
    }
end

--- Affiche un résumé des tests
---@return boolean all_passed True si tous les tests ont passé
function M.print_summary()
    print("")
    print("============================================")
    print("  RÉSUMÉ DES TESTS")
    print("============================================")
    print(string.format("  %s✓ Passed: %d%s",
        M.colors.green, test_results.passed, M.colors.reset))

    if test_results.failed > 0 then
        print(string.format("  %s✗ Failed: %d%s",
            M.colors.red, test_results.failed, M.colors.reset))
    end

    if test_results.warnings > 0 then
        print(string.format("  %s⚠ Warnings: %d%s",
            M.colors.yellow, test_results.warnings, M.colors.reset))
    end

    print("============================================")

    return test_results.failed == 0
end

-- =============================================================================
-- UTILITAIRES
-- =============================================================================

--- Attend un certain nombre de secondes
---@param seconds number Nombre de secondes
function M.sleep(seconds)
    local cmd = "sleep " .. tostring(seconds)
    M.run(cmd)
end

--- Attend qu'une condition soit vraie (avec timeout)
---@param check_fn function Fonction retournant boolean
---@param timeout number Timeout en secondes
---@param interval number? Intervalle entre les checks (défaut: 2)
---@param msg string? Message à afficher pendant l'attente
---@return boolean success True si la condition est devenue vraie
function M.wait_for(check_fn, timeout, interval, msg)
    interval = interval or 2
    local elapsed = 0

    while elapsed < timeout do
        if check_fn() then
            return true
        end

        if msg then
            io.write(string.format("\r  %s... %ds", msg, elapsed))
            io.flush()
        end

        M.sleep(interval)
        elapsed = elapsed + interval
    end

    if msg then print("") end
    return false
end

--- Retourne le répertoire racine du projet
---@param script_path string? Chemin du script appelant (optionnel)
---@return string path Chemin absolu du répertoire racine du projet
function M.get_project_root(script_path)
    if script_path then
        -- Remonter depuis tests/lua/xxx.lua vers la racine
        local root, _ = M.run("cd $(dirname '" .. script_path .. "')/../.. && pwd")
        return root:gsub("%s+$", "")
    end

    -- Fallback: utiliser pwd
    local pwd, _ = M.run("pwd")
    return pwd:gsub("%s+$", "")
end

--- Vérifie les prérequis (docker, curl)
---@return boolean ok True si tous les prérequis sont présents
function M.check_prerequisites()
    M.log_section("Vérification des prérequis")

    local docker_ok = M.run_ok("docker --version")
    M.assert_true(docker_ok, "Docker installé", "Docker non installé")
    if not docker_ok then return false end

    local curl_ok = M.run_ok("curl --version")
    M.assert_true(curl_ok, "Curl installé", "Curl non installé")
    if not curl_ok then return false end

    return true
end

--- Compte les lignes d'un fichier (excluant les lignes vides et commentaires)
---@param filepath string Chemin du fichier
---@return number count Nombre de lignes
function M.count_lines(filepath)
    local cmd = string.format("wc -l < '%s' 2>/dev/null || echo 0", filepath)
    local output, _ = M.run(cmd)
    return tonumber(output:match("%d+")) or 0
end

--- Compte les entrées JSON dans un fichier (une par ligne)
---@param filepath string Chemin du fichier
---@return number count Nombre d'entrées JSON
function M.count_json_lines(filepath)
    local cmd = string.format("grep -c '^{' '%s' 2>/dev/null || echo 0", filepath)
    local output, _ = M.run(cmd)
    return tonumber(output:match("%d+")) or 0
end

return M
