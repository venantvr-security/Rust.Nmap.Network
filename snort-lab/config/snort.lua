-- Snort 3 Configuration for IDS Lab
-- Minimal config for testing nmap evasion techniques

-- Network variables
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Configure IPS
ips = {
    enable_builtin_rules = true,
    include = '/etc/snort/local.rules',
}

-- Enable alerts
alert_fast = {
    file = true,
}

-- Enable logging
unified2 = {
    limit = 128,
}

-- Stream configuration for packet reassembly
stream = { }
stream_tcp = { }
stream_udp = { }

-- HTTP inspection
http_inspect = { }

-- Port scan detection
port_scan = {
    protos = 'all',
    scan_types = 'all',
    sense_level = 'low',
}

-- Normalizers
normalizer = {
    tcp = {
        ips = true,
    },
    ip4 = {
        df = true,
    },
}
