# ZEEK Level 2 - Basic
# Detects common scans and obvious attacks

@load base/frameworks/notice
@load base/protocols/conn

module IDS_Basic;

export {
    redef enum Notice::Type += {
        ICMP_Flood,
        Port_Scan_Basic,
    };
}

global icmp_count: table[addr] of count &default=0 &read_expire=1sec;
global scan_count: table[addr] of count &default=0 &read_expire=1min;

event icmp_sent(c: connection, icmp: icmp_conn)
{
    ++icmp_count[c$id$orig_h];
    if (icmp_count[c$id$orig_h] > 50)
    {
        NOTICE([
            $note=ICMP_Flood,
            $msg=fmt("ICMP flood from %s", c$id$orig_h),
            $src=c$id$orig_h
        ]);
    }
}

event connection_attempt(c: connection)
{
    ++scan_count[c$id$orig_h];
    if (scan_count[c$id$orig_h] > 50)
    {
        NOTICE([
            $note=Port_Scan_Basic,
            $msg=fmt("Port scan from %s (%d attempts)", c$id$orig_h, scan_count[c$id$orig_h]),
            $src=c$id$orig_h
        ]);
    }
}
