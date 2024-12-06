#ifndef _XT_DNP3_H
#define _XT_DNP3_H


#include <linux/types.h>


struct pkt_dnp3_header {
    __u8 sync1;                         /* Synchronisation byte 1 */
    __u8 sync2;                         /* Synchronisation byte 2 */
    __u8 length;                        /* Length */
    __u8 control;                       /* Control */
    __u16 daddr;                        /* Destination address */
    __u16 saddr;                        /* Source address */
    __u16 checksum;                     /* Checksum */
};

struct xt_dnp3_rule {
    __u16 daddr[2];                     /* Destination address */
    __u16 saddr[2];                     /* Source address */
    __u8 fc[32];                        /* Function code */
    __u32 set;                          /* Set flags */
    __u32 invert;                       /* Invert flags */
};

struct xt_dnp3_session {
    __u32 src;                          /* Source IP */
    __u32 dest;                         /* Destination IP */
    __u8 saddr;                         /* Source address */
    __u8 daddr;                         /* Destination address */
    __u16 seq;                          /* Transport sequence */
    __u8 active;
};


#define DNP3_LINK_HDR_LENGTH            (10)

#define DNP3_TSPT_HDR_LENGTH            (1)
#define DNP3_TSPT_HDR_FIRST_MASK        (0x40)
#define DNP3_TSPT_HDR_FINAL_MASK        (0x80)
#define DNP3_TSPT_HDR_SEQUENCE_MASK     (0x3f)

#define DNP3_APPL_CTRL_OFFSET           (0)
#define DNP3_APPL_FC_OFFSET             (1)


/*
    The XT_DNP3_SESSION definition specifies the number of multi-frame messages
    to track concurrently within the xt_dnp3 kernel module.
*/

#define XT_DNP3_SESSIONS                (16)

#define XT_DNP3_FLAG_CHECKSUM           (0x00000001)
#define XT_DNP3_FLAG_DADDR              (0x00000002)
#define XT_DNP3_FLAG_SADDR              (0x00000004)
#define XT_DNP3_FLAG_FC                 (0x00000008)
#define XT_DNP3_FLAG_MASK               (0x0000000f)


#endif
