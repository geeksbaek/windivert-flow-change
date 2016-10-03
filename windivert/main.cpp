/*
  Usage: windivert-example.exe [origin_ip] [origin_port] [modified_ip] [modified_port]
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
#include "FlowChanger.h"

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
static bool Compare(UINT8 *addr1, std::string addr2);

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
  PWINDIVERT_TCPHDR tcp_header;
  UINT payload_len;

  TCPPACKET reset0;
  PTCPPACKET reset = &reset0;

  std::string origin_dst_ip, modified_dst_ip;
  std::string origin_dst_port, modified_dst_port;

  UINT8 origin_dst_ip_uint8[4], modified_dst_ip_uint8[4];
  UINT16 origin_dst_port_uint16, modified_dst_port_uint16;

  // Check arguments.
  switch (argc)
  {
  case 5:
    origin_dst_ip = std::string(argv[1]);
    origin_dst_port = std::string(argv[2]);
    modified_dst_ip = std::string(argv[3]);
    modified_dst_port = std::string(argv[4]);

    inet_pton(AF_INET, origin_dst_ip.c_str(), origin_dst_ip_uint8);
    inet_pton(AF_INET, modified_dst_ip.c_str(), modified_dst_ip_uint8);

    origin_dst_port_uint16 = atoi(origin_dst_port.c_str());
    modified_dst_port_uint16 = atoi(modified_dst_port.c_str());

    break;
  default:
    fprintf(stderr, "usage: %s [origin_ip] [origin_port] [modified_ip] [modified_port]\n",
      argv[0]);
    fprintf(stderr, "examples:\n");
    fprintf(stderr, "\t%s 192.168.0.1 80 192.168.0.2 8080\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // Initialize all packets.
  PacketIpTcpInit(reset);
  reset->tcp.Rst = 1;
  reset->tcp.Ack = 1;

                              // Get console for pretty colors.
  console = GetStdHandle(STD_OUTPUT_HANDLE);

  std::string filter = 
    "("
    "(outbound and ip.DstAddr == " + origin_dst_ip + " and "
    "tcp.DstPort == " + origin_dst_port + ") or "
    "(inbound and ip.SrcAddr == " + modified_dst_ip + " and "
    "tcp.SrcPort == " + modified_dst_port + ")"
    ")";

  std::cout << "filter : " << filter << std::endl;

  // Divert traffic matching the filter:
  handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, priority, 0);

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
      NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);

    if (ip_header == NULL || tcp_header == NULL)
    {
      continue;
    }

    if (ip_header != NULL && tcp_header != NULL)
    {
      UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
      UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;

      SetConsoleTextAttribute(console, FOREGROUND_GREEN);
      fputs("origin packet   : ", stdout);
      SetConsoleTextAttribute(console,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

      printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
        src_addr[0], src_addr[1], src_addr[2], src_addr[3],
        dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);

      // if Outbound
      if (Compare(dst_addr, origin_dst_ip)) {
        memcpy(dst_addr, modified_dst_ip_uint8, sizeof(modified_dst_ip_uint8));
        tcp_header->DstPort = htons(modified_dst_port_uint16);
      }
      // else if Inbound
      else if (Compare(src_addr, modified_dst_ip)) {
        memcpy(src_addr, origin_dst_ip_uint8, sizeof(modified_dst_ip_uint8));
        tcp_header->SrcPort = htons(origin_dst_port_uint16);
        recv_addr.Direction = !recv_addr.Direction;
      }
      else {
        continue;
      }

      SetConsoleTextAttribute(console, FOREGROUND_RED);
      fputs("modified packet : ", stdout);
      SetConsoleTextAttribute(console,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

      printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
        src_addr[0], src_addr[1], src_addr[2], src_addr[3],
        dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
   
      WinDivertHelperCalcChecksums(packet, packet_len, 0);

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

static bool Compare(UINT8 *addr1, std::string addr2) {
  UINT8 temp_addr[4];
  inet_pton(AF_INET, addr2.c_str(), temp_addr);
  for (int i = 0; i < 4; i++) {
    if (temp_addr[i] != addr1[i]) {
      return false;
    }
  }
  return true;
}
