/*
* DESCRIPTION:
* This is a simple traffic filter/firewall using WinDivert.
*
* usage: netfilter.exe windivert-filter [priority]
*
* Any traffic that matches the windivert-filter will be blocked using one of
* the following methods:
* - TCP: send a TCP RST to the packet's source.
* - UDP: send a ICMP(v6) "destination unreachable" to the packet's source.
* - ICMP/ICMPv6: Drop the packet.
*
* This program is similar to Linux's iptables with the "-j REJECT" target.
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <WS2tcpip.h>
#include <iostream>
#include "windivert.h"

#define MAXBUF  0xFFFF

/*
* Pre-fabricated packets.
*/
typedef struct
{
  WINDIVERT_IPHDR ip;
  WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

/*
* Prototypes.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet);
static void PacketIpTcpInit(PTCPPACKET packet);

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
  HANDLE handle, console;
  INT16 priority = 0;
  unsigned char packet[MAXBUF];
  UINT packet_len;
  WINDIVERT_ADDRESS recv_addr, send_addr;
  PWINDIVERT_IPHDR ip_header;
  UINT payload_len;

  TCPPACKET reset0;
  PTCPPACKET reset = &reset0;

  std::string origin_dst, modifid_dst;

  // Check arguments.
  switch (argc)
  {
  case 3:
    origin_dst = std::string(argv[1]);
    modifid_dst = std::string(argv[2]);
    break;
  default:
    fprintf(stderr, "usage: %s Origin_Dst_Address Modifed_Dst_Address\n",
      argv[0]);
    fprintf(stderr, "examples:\n");
    fprintf(stderr, "\t%s 192.168.0.1 192.168.0.2\n", argv[0]);
    fprintf(stderr, "\t%s http://www.naver.com\/ http://localhost:8080\/\n",
      argv[0]);
    exit(EXIT_FAILURE);
  }

  // Initialize all packets.
  PacketIpTcpInit(reset);
  reset->tcp.Rst = 1;
  reset->tcp.Ack = 1;

                              // Get console for pretty colors.
  console = GetStdHandle(STD_OUTPUT_HANDLE);

  // Divert traffic matching the filter:
  handle = WinDivertOpen(
    ("outbound and ip.DstAddr == " + origin_dst).c_str(),
    WINDIVERT_LAYER_NETWORK, priority, 0);
  if (handle == INVALID_HANDLE_VALUE)
  {
    if (GetLastError() == ERROR_INVALID_PARAMETER)
    {
      fprintf(stderr, "error: filter syntax error\n");
      exit(EXIT_FAILURE);
    }
    fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
      GetLastError());
    exit(EXIT_FAILURE);
  }

  // Main loop:
  while (TRUE)
  {
    // Read a matching packet.
    if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
      &packet_len))
    {
      fprintf(stderr, "warning: failed to read packet\n");
      continue;
    }

    WinDivertHelperParsePacket(packet, packet_len, &ip_header,
      NULL, NULL, NULL, NULL, NULL, NULL, &payload_len);

    if (ip_header == NULL)
    {
      continue;
    }

    // Dump packet info: 
    SetConsoleTextAttribute(console, FOREGROUND_RED);
    fputs("BLOCK ", stdout);
    SetConsoleTextAttribute(console,
      FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    if (ip_header != NULL)
    {
      UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
      UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
      printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
        src_addr[0], src_addr[1], src_addr[2], src_addr[3],
        dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);

   
      inet_pton(AF_INET, modifid_dst.c_str(), dst_addr);

      WinDivertHelperCalcChecksums(packet, packet_len,
        WINDIVERT_HELPER_NO_REPLACE);

      if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL)) {
        fprintf(stderr, "\nwarning: failed to send (%d)", GetLastError());
      }

    }

    putchar('\n');
  }
}

/*
* Initialize a PACKET.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
  memset(packet, 0, sizeof(WINDIVERT_IPHDR));
  packet->Version = 4;
  packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
  packet->Id = ntohs(0xDEAD);
  packet->TTL = 64;
}

/*
* Initialize a TCPPACKET.
*/
static void PacketIpTcpInit(PTCPPACKET packet)
{
  memset(packet, 0, sizeof(TCPPACKET));
  PacketIpInit(&packet->ip);
  packet->ip.Length = htons(sizeof(TCPPACKET));
  packet->ip.Protocol = IPPROTO_TCP;
  packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}
