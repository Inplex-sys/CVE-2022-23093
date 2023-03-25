# CVE-2022-23093 FreeBSD Stack-Based Overflow

### Informations
The shellcode that is used by default is **FreeBSD/x86-64 - execve - 28 bytes from Gitsnik** change it and put your own one for starting

### Details of Vulnerability
The ping utility, used to solicit an ICMP ECHO_RESPONSE from a host or gateway, is invoked with an IPv4 target, either IPv4-host or IPv4-mcast-group, through the mandatory ECHO_REQUEST data gram of the ICMP protocol. The ECHO_REQUEST data gram consists of an IP and ICMP header, followed by a "struct timeval" and a varying number of "pad" bytes to fill the packet.

As per the FreeBSD Project's security advisory, the ping utility retrieves raw IP packets from the network to process responses within the pr_pack() function. In response processing, ping reconstructs the IP header, ICMP header, and, if present, a "quoted packet" representing the packet that caused the ICMP error. The quoted packet also includes an IP header and an ICMP header.

The pr_pack() function copies the IP and ICMP headers received into stack buffers for further processing. However, it fails to account for the possibility of IP option headers following the IP header in either the response or the quoted packet. In the presence of IP options, pr_pack() overflows the destination buffer by up to 40 bytes.

### Technical Analysis
The ping utility runs in userspace, and upon invoking the ping command, the binary located at /sbin/ping is executed. The source code for the utility is publicly available on the FreeBSD source. The vulnerable function, pr_pack(), prints the ICMP packet response information to stdout in a string format, such as "64 bytes from 1.3.3.7: icmp_seq=1 ttl=55 time=13.7 ms."


![image](https://user-images.githubusercontent.com/69421356/222618600-e4a66318-a0f6-4c3f-9827-de1d735451fb.png)


The ICMP packet, in both request and response, comprises IP headers with an optional Options field, as illustrated in the diagram above. In a malicious attack, these IP Options are enabled and filled with non-null bytes.

If an ICMP packet is malformed or deliberately tampered with en route to the destination host, and IP Options are enabled in the original echo request, the pr_pack() function fails to allocate sufficient space on the stack to accommodate the IP Options' presence, resulting in stack overflow.

In these error cases, the response from the destination host may also include a "quoted packet" in the data section, identifying the specific packet that caused the ICMP error. The pr_pack() function overflows the stack when the quoted packet includes ICMP headers.
