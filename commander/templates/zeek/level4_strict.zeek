# ZEEK Level 4 - Strict
# High sensitivity - detects most techniques

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns

module IDS_Strict;

export {
    redef enum Notice::Type += {
        ICMP_Activity,
        Port_Scan,
        HTTP_Request,
        SYN_Flood,
        Connection_Attempt,
        Slow_Scan,
    };
}

global icmp_count: table[addr] of count &default=0 &read_expire=1sec;
global scan_count: table[addr] of count &default=0 &read_expire=1min;
global syn_count: table[addr] of count &default=0 &read_expire=30sec;
global slow_scan: table[addr] of count &default=0 &read_expire=5min;

event icmp_sent(c: connection, icmp: icmp_conn)
{
    NOTICE([
        $note=ICMP_Activity,
        $msg=fmt("ICMP from %s to %s", c$id$orig_h, c$id$resp_h),
        $src=c$id$orig_h
    ]);
}

event connection_attempt(c: connection)
{
    ++scan_count[c$id$orig_h];
    ++slow_scan[c$id$orig_h];

    if (scan_count[c$id$orig_h] > 5)
    {
        NOTICE([
            $note=Port_Scan,
            $msg=fmt("Port scan from %s (%d attempts)", c$id$orig_h, scan_count[c$id$orig_h]),
            $src=c$id$orig_h,
            $identifier=cat(c$id$orig_h)
        ]);
    }

    if (slow_scan[c$id$orig_h] > 3)
    {
        NOTICE([
            $note=Slow_Scan,
            $msg=fmt("Slow scan detected from %s", c$id$orig_h),
            $src=c$id$orig_h
        ]);
    }
}

event new_connection(c: connection)
{
    ++syn_count[c$id$orig_h];

    NOTICE([
        $note=Connection_Attempt,
        $msg=fmt("Connection %s:%d -> %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p),
        $src=c$id$orig_h
    ]);

    if (syn_count[c$id$orig_h] > 10)
    {
        NOTICE([
            $note=SYN_Flood,
            $msg=fmt("SYN flood from %s", c$id$orig_h),
            $src=c$id$orig_h
        ]);
    }
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    NOTICE([
        $note=HTTP_Request,
        $msg=fmt("HTTP %s %s from %s", method, original_URI, c$id$orig_h),
        $src=c$id$orig_h
    ]);
}
