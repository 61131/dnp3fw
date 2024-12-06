# Linux DNP3 Filter Module #

## Overview ##

DNP3 is an industrial communication protocol developed by Westronic, Inc. as an interim solution - while the IEC 60870-5 protocol was under development - to allow interoperability between various SCADA components for electrical transmission and control. This protocol incorporates a number of elements designed to allow reliable communications in the adverse environments that electric utility automation systems are subjected to, such as distortion induced by EMI, aging components and poor transmission media.

As a protocol, DNP3 offers a number of features of flexibility and functionality beyond that of other communication protocols including:

*   Object based data representation
*   Data link and application layer confirmation
*   Broadcast messages
*   Time synchronisation and time-stamped events
*   Secure configuration and file transfers
*   Interoperability between multi-vendor devices

As a result, DNP3 is widely used as the communication protocol of choice for electrical, water and waste water telemetry and control networks.

An iptables-based filter for DNP3, based upon complex packet payload matching, has been described previously by Jeyasingam Nivethan and Mauricio Papa in their paper "[A Linux-based firewall for the DNP3 protocol](http://ieeexplore.ieee.org/abstract/document/7568963/)" presented at the 2016 IEEE Symposium on Technologies for Homeland Security (HST). This paper describes an approach for packet matching using the u32 match filter that permits the direct matching of packets based upon payload contents. This approach however requires a deep understanding of the network encoding of the DNP3 protocol and bit manipulation operations provided by this filter rule and in turn, is prone to human error.

## Packet Format ##

DNP3 message packets incorporate a complex, multi-layer structure supporting transport over a diverse range of communications networks.

### Link Layer ###

The data link layer maintains a logical link between two devices to facilitate the transfer of DNP3 messages. The data link layer frame has a fixed 10-byte header and a variable length data payload which is transmitted to the higher transport and application layers of the DNP3 protocol stack. The maximum length of the data section is 250 bytes, which is encoded as 282 bytes by way of the inclusion of a 16-bit CRC for every 16 bytes of data. In this way, the maximum DNP3 data link layer frame is 292 bytes in length.

![DNP3 Link Layer](https://github.com/61131/dnp3fw/raw/main/images/packet-linklayer.png?raw=true)

With regard to specific fields within the DNP3 link layer:

*   **Start -** The two-byte start field serves as a synchronisation point for frame parsing and always contains the value 0x0564.
*   **Length -** The length field contains the number of bytes in the remainder of the frame (excluding CRC bytes).
*   **Link Control -** The link control field contains data that controls DNP3 frame message flow, sequencing and message functions.
*   **Destination address -** The destination address field is a two-byte, little-endian field that specifies the address of the DNP3 station to which the message is directed. 
*   **Source address -** The source address field is a two-byte, little-endian field that specifies the address of the DNP3 station from where the message originates. 

The DNP3 filter module allows matching on the source and destination address fields specified in the DNP3 link layer header. It should be noted that for a DNP3 packet to be recognised as such by the DNP3 filter module, the packet must contain a valid DNP3 link layer frame. For this reason, it is recommended that the DNP3 filter module is used to explicitly specify allowed DNP3 communications while rejecting all other traffic.

### Transport Layer ###

The transport layer handles message fragmentation and allows application messages to be transmtted larger than a single DNP3 data link layer frame. The transport layer is a single byte in size and includes flags to identify the first and final frames of a sequence and a sequence number, which is incremented for each frame.

### Application Layer ###

The application layer contains DNP3 request and response messages. Application messages may be fragmented across multiple DNP3 frame messages and reach lengths of up to 2048 or 4096 bytes in length.

![DNP3 Application Layer](https://github.com/61131/dnp3fw/raw/main/images/packet-applicationlayer.png?raw=true)

While regard to specific fields within the DNP3 application layer:

*   **Function Code -** The function code field specifies the purpose of the message and is used in both request and response messages. The DNP3 filter module allows matching on the function code field specified in the DNP3 application layer.

| Function Code                                              | Value |
|:-----------------------------------------------------------|:------|
| Confirm                                                    | 0     |
| Read                                                       | 1     |
| Write                                                      | 2     |
| Select                                                     | 3     |
| Operate                                                    | 4     |
| Direct Operate                                             | 5     |
| Direct Operate (without acknowledgement)                   | 6     |
| Freeze Counters                                            | 7     |
| Freeze Counters (without acknowledgement)                  | 8     |
| Freeze & Clear Counters                                    | 9     |
| Freeze & Clear Counters (without acknowlegement)           | 10    |
| Freeze Counters (with time-stamp)                          | 11    |
| Freeze Counters (with time-stamp, without acknowledgement) | 12    |
| Cold Restart                                               | 13    |
| Warm Restart                                               | 14    |
| Initialise Data                                            | 15    |
| Initialise Application                                     | 16    |
| Start Application                                          | 17    |
| Stop Application                                           | 18    |
| Save Configuration                                         | 19    |
| Enable Unsolicited Messages                                | 20    |
| Disable Unsolicited Messages                               | 21    |
| Assign Class                                               | 22    |
| Delay Measurement                                          | 23    |
| Record Current Time                                        | 24    |
| Open File                                                  | 25    |
| Close File                                                 | 26    |
| Delete File                                                | 27    |
| Get File Information                                       | 28    |
| Authenticate                                               | 29    |
| Abort                                                      | 30    |
| Activate Configuration                                     | 31    |
| Authentication Request                                     | 32    |
| Authentication Request (without acknowledgement)           | 33    |
| Response                                                   | 129   |
| Unsolicited Response                                       | 130   |
| Authentication Response                                    | 131   |

## Installation ##

The DNP3 filter module has been built on [Ubuntu 24.04.1 LTS](http://releases.ubuntu.com/noble/) with GNU/Linux 6.8.12 and iptables 1.8.11. This installation involves the patching, building and installation of iptables and the build and installation of the Linux kernel DNP3 filter module.

### Patching, building and installation of iptables ###

    ~/git/dnp3fw$ tar xf iptables-1.8.11.tar.xz
    ~/git/dnp3fw$ cd iptables-1.8.11
    ~/git/dnp3fw/iptables-1.8.11$ patch -p1 < ../iptables-1.8.11-dnp3fw.patch
    patching file extensions/libxt_dnp3.c
    patching file include/linux/netfilter/xt_dnp3.h
    ~/git/dnp3fw/iptables-1.8.11$ 

There are no specific configuration or build requirements for iptables following the application of the DNP3 filter patch as shown above. For building and installing iptables, please refer to the INSTALL file in the iptables source folder.

### Build and installation of DNP3 filter module ###

    ~/git/dnp3fw$ cd src/kernel
    ~/git/dnp3fw/src/kernel$ make
    make -C /lib/modules/`uname -r`/build M=$PWD
    make[1]: Entering directory '/home/rob/build/kernel/linux-6.8.12'
      CC [M]  /home/rob/git/dnp3fw/src/kernel/xt_dnp3.o
      MODPOST /home/rob/git/dnp3fw/src/kernel/Module.symvers
      CC      /home/rob/git/dnp3fw/src/kernel/xt_dnp3.mod.o
      LD [M]  /home/rob/git/dnp3fw/src/kernel/xt_dnp3.ko
    make[1]: Leaving directory '/home/rob/build/kernel/linux-6.8.12'
    ~/git/dnp3fw/src/kernel$ sudo modprobe x_tables
    ~/git/dnp3fw/src/kernel$ sudo insmod xt_dnp3.ko
    ~/git/dnp3fw/src/kernel$

The build of the DNP3 filter module is dependent upon Linux kernel source files. The location of these source files can be specified using the environment variable KDIR prior to calling make. If this source location is not specified, the make file will default to looking for these source files in the build location employed for the current kernel (in /home/rob/build/kernel/linux-6.8.12 in the example above).

The DNP3 filter module can then be loaded using insmod. Note that this kernel module is dependent upon x_tables functionality and as such, if this module is not loaded or built-in to your kernel image, an unknown symbol error will be returned by insmod. This can be simply corrected by loading x_tables module prior to loading the DNP3 filter module via insmod.

Additionally, while not a problem with earlier versions of Ubuntu, with 24.04.1 LTS, it was also found necessary to remove the distribution iptables packages and delete the distribution libip4tc2 and libxtables library files to prevent conflict between these and the newly built versions.

## Rules Specification ##

With this DNP3 filter module, extended packet matching can be specified using iptables with the *-m* or *--match* options, following my the protocol match name "dnp3". It is using this extended packet matching mechanism that DNP3 specific filtering rules can defined based upon DNP3 frame fields.

Supported matching options include:

| Parameter                                 | Descripton              |
|:------------------------------------------|:------------------------|
| `[!] --destination-addr addr[:addr]`      | Destination address(es) |
| `[!] --daddr addr[:addr]`                 | Destination address(es) |
| `[!] --source-addr addr[:addr]`           | Source address(es)      |
| `[!] --saddr addr[:addr]`                 | Source address(es)      |
| `[!] --function-code function[,function]` | Function code(s)        |
| `[!] --fc function[,function]`            | Function code(s)        |

Due to the specificity of rule matching by the DNP3 filter module, it is recommended that specific rules to permit allowed DNP3 traffic are establish while all other traffic is rejected by default.

Examples:

    # Set default INPUT policy to drop packets
    iptables -P DROP
    # Accept new inbound connections to TCP port 20000
    iptables -A INPUT -p tcp --dport 20000 -m state --state NEW -j ACCEPT
    # Accept DNP3 messages with confirm, read and write commands for address 1
    iptables -A INPUT -p tcp --dport 20000 -m dnp3 --daddr 1 --fc 0,1,2 -j ACCEPT
    # Drop DNP3 cold and warm restart messages
    iptables -A INPUT -p tcp --dport 20000 -m dnp3 --fc 13,14 -j DROP
    # Log DNP3 authentication requests
    iptables -A INPUT -p tcp --dport 20000 -m dnp3 --fc 32,33 -j LOG

## Links ##

*   [DNP Organization](http://www.dnp.org)

    The DNP Users Group is a California nonprofit public mutual benefit nonprofit Corporation, operating as a nonprofit organization pursuant to United States IRS code 501(c)(6). The primary purpose of the corporation is to maintain and promote the Distributed Network Protocol (DNP3), a non-proprietary, standards based communication protocol widely used in the utility industry. The DNP Users Group supports the DNP3 communication protocol standards as appropriate to the needs of the membership through development and maintenance of the technical documentation necessary to facilitate interoperability of products and systems used in the utility industry based on these standards. Additionally, the DNP Users Group provides a forum in which the various stakeholders in the utility industry can work cooperatively as members of a common organization, and implements educational and promotional activities that increase awareness and deployment of the DNP3 protocol in the utility industry.

    The DNP3 protocol specification can be obtained through membership to the DNP Users Group.

*   [DNP3 - Wikipedia](https://en.wikipedia.org/wiki/DNP3)

    General overview and description of the DNP3 protocol.

*   [Linux Modbus/TCP Firewall Module](https://github.com/61131/modbusfw)

    Similar Linux kernel filter module by the same author for Modbus/TCP protocol.
