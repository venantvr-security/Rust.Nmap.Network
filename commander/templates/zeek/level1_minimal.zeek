# ZEEK Level 1 - Minimal (Most Permeable)
# Only detects the most obvious attacks

@load base/frameworks/notice

module IDS_Minimal;

export {
    redef enum Notice::Type += {
        ICMP_Flood,
    };
}

global icmp_count: table[addr] of count &default=0 &read_expire=1sec;

event icmp_sent(c: connection, icmp: icmp_conn)
{
    ++icmp_count[c$id$orig_h];
    if (icmp_count[c$id$orig_h] > 100)
    {
        NOTICE([
            $note=ICMP_Flood,
            $msg=fmt("ICMP flood from %s", c$id$orig_h),
            $src=c$id$orig_h
        ]);
    }
}
