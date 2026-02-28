// =============================================================================
// IDS LAB COMMANDER - Tests d'intégration
// =============================================================================
//
// Ces tests vérifient le bon fonctionnement des opérations Docker Compose
// et des APIs du commander.
//
// EXÉCUTION:
// cargo test --test integration_tests
//
// PRÉREQUIS:
// - Docker daemon en cours d'exécution
// - Commander non lancé (ou sur un port différent)
// =============================================================================

use std::process::Command;
use std::time::Duration;
use std::thread;

fn run_command(cmd: &str, args: &[&str]) -> (bool, String, String) {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .expect("Failed to execute command");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn container_running(name: &str) -> bool {
    let (success, stdout, _) = run_command("docker", &["ps", "--format", "{{.Names}}"]);
    success && stdout.contains(name)
}

fn wait_for_container(name: &str, running: bool, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        if container_running(name) == running {
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
fn test_docker_available() {
    let (success, _, _) = run_command("docker", &["version"]);
    assert!(success, "Docker doit être disponible");
}

#[test]
fn test_docker_compose_available() {
    let (success, _, _) = run_command("docker", &["compose", "version"]);
    assert!(success, "Docker Compose doit être disponible");
}

#[test]
#[ignore]
fn test_suricata_lab_lifecycle() {
    let lab_dir = "../suricata-lab";

    let _ = run_command("docker", &["compose", "-f", &format!("{}/docker-compose.yml", lab_dir), "down"]);
    thread::sleep(Duration::from_secs(2));

    let (success, _, stderr) = run_command("docker", &[
        "compose", "-f", &format!("{}/docker-compose.yml", lab_dir),
        "up", "-d", "--build"
    ]);
    assert!(success, "Le lab Suricata doit démarrer: {}", stderr);

    assert!(wait_for_container("suricata_ids", true, 30), "suricata_ids doit démarrer");
    assert!(wait_for_container("target_suricata", true, 30), "target_suricata doit démarrer");

    let (success, _, stderr) = run_command("docker", &[
        "compose", "-f", &format!("{}/docker-compose.yml", lab_dir), "down"
    ]);
    assert!(success, "Le lab Suricata doit s'arrêter: {}", stderr);

    assert!(wait_for_container("suricata_ids", false, 30), "suricata_ids doit s'arrêter");
}
