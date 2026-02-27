# Zeek Local Script - IDS Lab
# Test scripts for nmap detection

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http

module IDS_Lab;

export {
    redef enum Notice::Type += {
        Port_Scan_Detected,
        SYN_Flood_Detected,
        HTTP_Request_Detected,
        Fragment_Detected,
    };
}

# Port scan detection
global scan_sources: table[addr] of count &default=0 &read_expire=1min;

event connection_attempt(c: connection)
{
    ++scan_sources[c$id$orig_h];

    if (scan_sources[c$id$orig_h] > 10)
    {
        NOTICE([
            $note=Port_Scan_Detected,
            $msg=fmt("Port scan detected from %s - %d connections", c$id$orig_h, scan_sources[c$id$orig_h]),
            $src=c$id$orig_h,
            $identifier=cat(c$id$orig_h)
        ]);
    }
}

# SYN flood detection
global syn_count: table[addr] of count &default=0 &read_expire=30sec;

event new_connection(c: connection)
{
    if (c$conn$proto == tcp)
    {
        ++syn_count[c$id$orig_h];

        if (syn_count[c$id$orig_h] > 50)
        {
            NOTICE([
                $note=SYN_Flood_Detected,
                $msg=fmt("Possible SYN flood from %s", c$id$orig_h),
                $src=c$id$orig_h
            ]);
        }
    }
}

# HTTP request logging
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    NOTICE([
        $note=HTTP_Request_Detected,
        $msg=fmt("HTTP %s %s from %s", method, original_URI, c$id$orig_h),
        $src=c$id$orig_h
    ]);
}

# Log all connections for analysis
event connection_state_remove(c: connection)
{
    print fmt("[%s] %s:%d -> %s:%d (%s)",
        c$conn$proto,
        c$id$orig_h, c$id$orig_p,
        c$id$resp_h, c$id$resp_p,
        c$conn$conn_state);
}
