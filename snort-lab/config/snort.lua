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

-- Binder for service detection and wizard
binder = {
    { when = { proto = 'tcp' }, use = { type = 'wizard' } },
    { when = { proto = 'udp' }, use = { type = 'wizard' } }
}

wizard = { }

-- Port scan detection (Snort 3.x syntax)
port_scan = {
    protos = 'all',
    scan_types = 'all',
    memcap = 10000000,
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
