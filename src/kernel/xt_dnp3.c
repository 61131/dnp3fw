#include <linux/kernel.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/netfilter/x_tables.h>

#include "xt_dnp3.h"


static int dnp3_mt_calculate_checksum(u8 *buff, u32 len);
static int dnp3_mt_check_checksum(u8 *buff, u32 len);
static int dnp3_mt_check_rule(const struct xt_mtchk_param *par);
static bool dnp3_mt_match_rule(const struct sk_buff *skb, struct xt_action_param *par);
static inline bool dnp3_mt_match_value(u16 value, u16 min, u16 max, bool invert);
static bool dnp3_mt_process_payload(const struct iphdr *iph, u8 *payload, ssize_t len, struct xt_action_param *par);
static struct xt_dnp3_session * dnp3_mt_session(const struct iphdr *iph, const struct pkt_dnp3_header *pkth, bool new_match);
static int dnp3_mt_validate_frame(u8 *buff, u32 len);
static int dnp3_mt_validate_header(u8 *buff, u32 len);


static const u16 _crc[256] = {
        0x0000, 0x365e, 0x6cbc, 0x5ae2, 0xd978, 0xef26, 0xb5c4, 0x839a,
        0xff89, 0xc9d7, 0x9335, 0xa56b, 0x26f1, 0x10af, 0x4a4d, 0x7c13,
        0xb26b, 0x8435, 0xded7, 0xe889, 0x6b13, 0x5d4d, 0x07af, 0x31f1,
        0x4de2, 0x7bbc, 0x215e, 0x1700, 0x949a, 0xa2c4, 0xf826, 0xce78,
        0x29af, 0x1ff1, 0x4513, 0x734d, 0xf0d7, 0xc689, 0x9c6b, 0xaa35,
        0xd626, 0xe078, 0xba9a, 0x8cc4, 0x0f5e, 0x3900, 0x63e2, 0x55bc,
        0x9bc4, 0xad9a, 0xf778, 0xc126, 0x42bc, 0x74e2, 0x2e00, 0x185e,
        0x644d, 0x5213, 0x08f1, 0x3eaf, 0xbd35, 0x8b6b, 0xd189, 0xe7d7,
        0x535e, 0x6500, 0x3fe2, 0x09bc, 0x8a26, 0xbc78, 0xe69a, 0xd0c4,
        0xacd7, 0x9a89, 0xc06b, 0xf635, 0x75af, 0x43f1, 0x1913, 0x2f4d,
        0xe135, 0xd76b, 0x8d89, 0xbbd7, 0x384d, 0x0e13, 0x54f1, 0x62af,
        0x1ebc, 0x28e2, 0x7200, 0x445e, 0xc7c4, 0xf19a, 0xab78, 0x9d26,
        0x7af1, 0x4caf, 0x164d, 0x2013, 0xa389, 0x95d7, 0xcf35, 0xf96b,
        0x8578, 0xb326, 0xe9c4, 0xdf9a, 0x5c00, 0x6a5e, 0x30bc, 0x06e2,
        0xc89a, 0xfec4, 0xa426, 0x9278, 0x11e2, 0x27bc, 0x7d5e, 0x4b00,
        0x3713, 0x014d, 0x5baf, 0x6df1, 0xee6b, 0xd835, 0x82d7, 0xb489,
        0xa6bc, 0x90e2, 0xca00, 0xfc5e, 0x7fc4, 0x499a, 0x1378, 0x2526,
        0x5935, 0x6f6b, 0x3589, 0x03d7, 0x804d, 0xb613, 0xecf1, 0xdaaf,
        0x14d7, 0x2289, 0x786b, 0x4e35, 0xcdaf, 0xfbf1, 0xa113, 0x974d,
        0xeb5e, 0xdd00, 0x87e2, 0xb1bc, 0x3226, 0x0478, 0x5e9a, 0x68c4,
        0x8f13, 0xb94d, 0xe3af, 0xd5f1, 0x566b, 0x6035, 0x3ad7, 0x0c89,
        0x709a, 0x46c4, 0x1c26, 0x2a78, 0xa9e2, 0x9fbc, 0xc55e, 0xf300,
        0x3d78, 0x0b26, 0x51c4, 0x679a, 0xe400, 0xd25e, 0x88bc, 0xbee2,
        0xc2f1, 0xf4af, 0xae4d, 0x9813, 0x1b89, 0x2dd7, 0x7735, 0x416b,
        0xf5e2, 0xc3bc, 0x995e, 0xaf00, 0x2c9a, 0x1ac4, 0x4026, 0x7678,
        0x0a6b, 0x3c35, 0x66d7, 0x5089, 0xd313, 0xe54d, 0xbfaf, 0x89f1,
        0x4789, 0x71d7, 0x2b35, 0x1d6b, 0x9ef1, 0xa8af, 0xf24d, 0xc413,
        0xb800, 0x8e5e, 0xd4bc, 0xe2e2, 0x6178, 0x5726, 0x0dc4, 0x3b9a,
        0xdc4d, 0xea13, 0xb0f1, 0x86af, 0x0535, 0x336b, 0x6989, 0x5fd7,
        0x23c4, 0x159a, 0x4f78, 0x7926, 0xfabc, 0xcce2, 0x9600, 0xa05e,
        0x6e26, 0x5878, 0x029a, 0x34c4, 0xb75e, 0x8100, 0xdbe2, 0xedbc,
        0x91af, 0xa7f1, 0xfd13, 0xcb4d, 0x48d7, 0x7e89, 0x246b, 0x1235
};


static struct xt_dnp3_session _session[XT_DNP3_SESSIONS];


static int 
dnp3_mt_calculate_checksum(u8 *buff, u32 len) {
    u16 crc;

    crc = 0;
    while (len--) {
        crc = (u16) ((crc >> 8) ^ (_crc[((crc ^ *buff++) & 0x00ff)]));
    }
    return (~crc & 0xffff);
}


static int
dnp3_mt_check_checksum(u8* buff, u32 len) {
    u16 crc1, crc2;

    if (len == 0) {
        return 0;
    }
    else if (len < 3) {
        return -EINVAL;
    }
    else {};

    crc1 = dnp3_mt_calculate_checksum(buff, len - 2);
    buff += (len - 2);
    crc2 = le16_to_cpu(*(u16 *)buff);

    return (crc1 == crc2) ? 0 : -EINVAL;
}


static int
dnp3_mt_check_rule(const struct xt_mtchk_param *par) {
    const struct xt_dnp3_rule *rule = par->matchinfo;
    
    if ((rule->set & ~XT_DNP3_FLAG_MASK) ||
            (rule->invert & ~XT_DNP3_FLAG_MASK)) {
        return -EINVAL;
    }
    return 0;
}


static bool
dnp3_mt_match_rule(const struct sk_buff *skb, struct xt_action_param *par) {
    const struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    ssize_t length;
    u8 *payload;

    switch (iph->protocol) {
        case IPPROTO_TCP:
            tcph = tcp_hdr(skb);
            payload = ((u8 *)tcph + (tcph->doff * 4));
            break;
        case IPPROTO_UDP:
            udph = udp_hdr(skb);
            payload = ((u8 *)udph + sizeof(struct udphdr));
            break;
        default:
            return false;
    }

    length = (skb_tail_pointer(skb) - payload);
    return dnp3_mt_process_payload(iph, payload, length, par);
}


static inline bool 
dnp3_mt_match_value(u16 value, 
        u16 min, 
        u16 max, 
        bool invert) {
    return (((value >= min) && (value <= max)) ^ invert);
}


static bool
dnp3_mt_process_payload(const struct iphdr *iph, 
        u8 *payload, 
        ssize_t len, 
        struct xt_action_param *par) {
    const struct xt_dnp3_rule *rule = par->matchinfo;
    const struct pkt_dnp3_header *pkth;
    struct xt_dnp3_session *session;
    u32 dest, src;
    u16 daddr, saddr;
    u8 expected, func, invert, match, seq, tspt;
    ssize_t length;

    for (; len > 0;) {
        if (len < sizeof(struct pkt_dnp3_header)) {
            return false;
        }
        if (dnp3_mt_validate_header(payload, DNP3_LINK_HDR_LENGTH) != 0) {
            return false;
        }
        pkth = (struct pkt_dnp3_header *) payload;

        /*
            At this point a valid DNP3 link layer header appears to have been received.
            For expediency, the source and destination addresses within this header are
            verified prior to performing checksum validation of the transport header and
            application segments within the DNP3 frame. If these conditions are defined
            and fail, further processing of the DNP3 frame can be aborted.
        */

        daddr = le16_to_cpu(pkth->daddr);
        if (rule->set & XT_DNP3_FLAG_DADDR) {
            if (!dnp3_mt_match_value(daddr,
                    rule->daddr[0],
                    rule->daddr[1],
                    !! (rule->invert & XT_DNP3_FLAG_DADDR))) {
                return false;		
            }
        }
        saddr = le16_to_cpu(pkth->saddr);
        if (rule->set & XT_DNP3_FLAG_SADDR) {
            if (!dnp3_mt_match_value(saddr,
                    rule->saddr[0],
                    rule->saddr[1],
                    !! (rule->invert & XT_DNP3_FLAG_SADDR))) {
                return false;		
            }		
        }

        if ((length = dnp3_mt_validate_frame(payload, len)) < 0) {
            return false;
        }

        /*
            If DNP3 application layer function code rules have been defined, the 
            transport and application layer headers are parsed. The splitting of longer 
            DNP3 messages across multiple frames adds a further layer of complexity to 
            message parsing and firewall rules application.

            For single frame DNP3 messages and the first frame of multi-frame DNP3 
            messages, the application function code is parsed and matched. For multi-
            frame DNP3 messages where the result of this processing is that the DNP3 
            message should be accepted, a session entry is established to permit the 
            transmission of subsequent frames of the DNP3 message.
        */

        for (;;) {
            if (!(rule->set & XT_DNP3_FLAG_FC)) {
                break;
            }
            src = ntohl(iph->saddr);
            dest = ntohl(iph->daddr);

            tspt = payload[DNP3_LINK_HDR_LENGTH];
            seq = tspt & DNP3_TSPT_HDR_SEQUENCE_MASK;
            
            if (tspt & DNP3_TSPT_HDR_FIRST_MASK) {
                func = payload[DNP3_LINK_HDR_LENGTH + DNP3_TSPT_HDR_LENGTH + DNP3_APPL_FC_OFFSET];
                match = ((rule->fc[func / 8] & (1 << (func % 8))) != 0);
                invert = !! (rule->invert & XT_DNP3_FLAG_FC);
                if (!(match ^ invert)) {
                    return false;
                }

                if (tspt & DNP3_TSPT_HDR_FINAL_MASK) {
                    break;
                }
                
                if (!(session = dnp3_mt_session(iph, pkth, true))) {
                    par->hotdrop = true;
                    return false;
                }
                session->dest = dest;
                session->src = src;
                session->daddr = daddr;
                session->saddr = saddr;
                session->seq = seq;
                session->active = true;
            }
            else {
                if (!(session = dnp3_mt_session(iph, pkth, false))) {
                    par->hotdrop = true;
                    return false;
                }
                expected = ((session->seq + 1) & DNP3_TSPT_HDR_SEQUENCE_MASK);
                if (seq != expected) {
                    par->hotdrop = true;
                    return false;
                }
                session->seq = seq;

                if (tspt & DNP3_TSPT_HDR_FINAL_MASK) {
                    session->active = false;
                }
            }

            break;
        }

        payload += length;
        len -= length;
    }

    return true;
}


static struct xt_dnp3_session *
dnp3_mt_session(const struct iphdr *iph, 
        const struct pkt_dnp3_header *pkth, 
        bool new_match) {
    struct xt_dnp3_session *session;
    u32 dest, src;
    u16 daddr, saddr;
    int index;

    dest = ntohl(iph->daddr);
    src = ntohl(iph->saddr);
    daddr = le16_to_cpu(pkth->daddr);
    saddr = le16_to_cpu(pkth->saddr);

    for (index = 0, session = NULL; index < ARRAY_SIZE(_session); ++index) {
        if ((_session[index].dest == dest) &&
                (_session[index].src == src) &&
                (_session[index].daddr == daddr) &&
                (_session[index].saddr == saddr)) {
            return &_session[index];
        }
        if ((new_match) &&
                (!session) &&
                (!_session[index].active)) {
            session = &_session[index];
        }
    }
    return session;
}


static int 
dnp3_mt_validate_frame(u8 *buff, u32 len) {
    struct pkt_dnp3_header *pkth;
    u32 bytes, index, length, segment;

    pkth = (struct pkt_dnp3_header *) buff;
    bytes = (pkth->length - 5);
    length = bytes + ((bytes / 16) * 2) + 10;
    if ((bytes % 16) != 0) {
        length += 2;
    }
    if (len < length) {
        return -1;
    }

    for (index = 10u; index < length; index += 18u) {
        segment = ((length - index) > 18u) ? 18u : (length - index);
        if (dnp3_mt_check_checksum(&buff[index], segment) != 0) {
            return -1;
        }
    }
    return length;
}


static int 
dnp3_mt_validate_header(u8 *buff, u32 len) {
    struct pkt_dnp3_header *pkth;

    if (len < sizeof(struct pkt_dnp3_header)) {
        return -1;
    }
    pkth = (struct pkt_dnp3_header *) buff;
    if ((pkth->sync1 != 0x05) ||
            (pkth->sync2 != 0x64) ||
            (pkth->length < 5) ||
            (dnp3_mt_check_checksum(buff, DNP3_LINK_HDR_LENGTH) != 0)) {
        return -1;
    }
    return 0;
}


static struct xt_match dnp3_mt_reg[] __read_mostly = {
    {
        .name       = "dnp3",
        .family     = NFPROTO_IPV4,
        .checkentry = dnp3_mt_check_rule,
        .match      = dnp3_mt_match_rule,
        .matchsize  = sizeof(struct xt_dnp3_rule),
        .me         = THIS_MODULE,
    },
};


static int __init
dnp3_mt_init(void) {
    return xt_register_matches(dnp3_mt_reg, ARRAY_SIZE(dnp3_mt_reg));
}


static void __exit
dnp3_mt_exit(void) {
    xt_unregister_matches(dnp3_mt_reg, ARRAY_SIZE(dnp3_mt_reg));
}


module_init(dnp3_mt_init);
module_exit(dnp3_mt_exit);

MODULE_AUTHOR("Rob Casey <rcasey@gmail.com>");
MODULE_LICENSE("GPL");

