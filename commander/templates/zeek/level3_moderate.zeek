# ZEEK Level 3 - Moderate
# Balanced detection - good for testing evasion

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http

module IDS_Moderate;

export {
    redef enum Notice::Type += {
        ICMP_Activity,
        Port_Scan,
        HTTP_Request,
        SYN_Flood,
    };
}

global icmp_count: table[addr] of count &default=0 &read_expire=1sec;
global scan_count: table[addr] of count &default=0 &read_expire=1min;
global syn_count: table[addr] of count &default=0 &read_expire=30sec;

event icmp_sent(c: connection, icmp: icmp_conn)
{
    ++icmp_count[c$id$orig_h];
    if (icmp_count[c$id$orig_h] > 10)
    {
        NOTICE([
            $note=ICMP_Activity,
            $msg=fmt("ICMP activity from %s", c$id$orig_h),
            $src=c$id$orig_h,
            $identifier=cat(c$id$orig_h)
        ]);
    }
}

event connection_attempt(c: connection)
{
    ++scan_count[c$id$orig_h];
    if (scan_count[c$id$orig_h] > 20)
    {
        NOTICE([
            $note=Port_Scan,
            $msg=fmt("Port scan from %s (%d attempts)", c$id$orig_h, scan_count[c$id$orig_h]),
            $src=c$id$orig_h,
            $identifier=cat(c$id$orig_h)
        ]);
    }
}

event new_connection(c: connection)
{
    if (c$conn$proto == tcp)
    {
        ++syn_count[c$id$orig_h];
        if (syn_count[c$id$orig_h] > 30)
        {
            NOTICE([
                $note=SYN_Flood,
                $msg=fmt("Possible SYN flood from %s", c$id$orig_h),
                $src=c$id$orig_h
            ]);
        }
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
