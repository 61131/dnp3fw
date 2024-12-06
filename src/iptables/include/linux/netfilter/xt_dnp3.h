#ifndef _XT_DNP3_H
#define _XT_DNP3_H


#include <linux/types.h>


struct xt_dnp3 {
    __u16 daddr[2];                     /* Destination address */
    __u16 saddr[2];                     /* Source address */
    __u8 fc[32];                        /* Function code */
    __u32 set;                          /* Set flags */
    __u32 invert;                       /* Invert flags */
};

#define XT_DNP3_FLAG_CHECKSUM           (0x00000001)
#define XT_DNP3_FLAG_DADDR              (0x00000002)
#define XT_DNP3_FLAG_SADDR              (0x00000004)
#define XT_DNP3_FLAG_FC                 (0x00000008)
#define XT_DNP3_FLAG_MASK               (0x0000000f)


#endif
