# ZEEK Level 5 - Paranoid (Maximum Security)
# Alerts on almost everything - very hard to evade

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl

module IDS_Paranoid;

export {
    redef enum Notice::Type += {
        PARANOID_ICMP,
        PARANOID_Connection,
        PARANOID_HTTP,
        PARANOID_DNS,
        PARANOID_SSL,
        PARANOID_UDP,
        PARANOID_Scan,
    };
}

# Log EVERYTHING
event icmp_sent(c: connection, icmp: icmp_conn)
{
    NOTICE([
        $note=PARANOID_ICMP,
        $msg=fmt("[PARANOID] ICMP %s -> %s", c$id$orig_h, c$id$resp_h),
        $src=c$id$orig_h
    ]);
}

event new_connection(c: connection)
{
    NOTICE([
        $note=PARANOID_Connection,
        $msg=fmt("[PARANOID] Connection %s:%d -> %s:%d (%s)",
            c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$conn$proto),
        $src=c$id$orig_h
    ]);
}

event connection_attempt(c: connection)
{
    NOTICE([
        $note=PARANOID_Scan,
        $msg=fmt("[PARANOID] Connection attempt %s -> %s:%d",
            c$id$orig_h, c$id$resp_h, c$id$resp_p),
        $src=c$id$orig_h
    ]);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    NOTICE([
        $note=PARANOID_HTTP,
        $msg=fmt("[PARANOID] HTTP %s %s from %s", method, original_URI, c$id$orig_h),
        $src=c$id$orig_h
    ]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    NOTICE([
        $note=PARANOID_HTTP,
        $msg=fmt("[PARANOID] HTTP Response %d %s to %s", code, reason, c$id$orig_h),
        $src=c$id$resp_h
    ]);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    NOTICE([
        $note=PARANOID_DNS,
        $msg=fmt("[PARANOID] DNS query for %s from %s", query, c$id$orig_h),
        $src=c$id$orig_h
    ]);
}

event ssl_established(c: connection)
{
    NOTICE([
        $note=PARANOID_SSL,
        $msg=fmt("[PARANOID] TLS/SSL established %s -> %s", c$id$orig_h, c$id$resp_h),
        $src=c$id$orig_h
    ]);
}

event udp_request(u: connection)
{
    NOTICE([
        $note=PARANOID_UDP,
        $msg=fmt("[PARANOID] UDP %s:%d -> %s:%d",
            u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p),
        $src=u$id$orig_h
    ]);
}

event connection_state_remove(c: connection)
{
    print fmt("[PARANOID] Connection closed: %s:%d -> %s:%d state=%s",
        c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$conn$conn_state);
}
