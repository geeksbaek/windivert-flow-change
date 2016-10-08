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
#include <map>
#include <tuple>

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
static void PrintTitle(std::string msg, int color, HANDLE console);
static void PrintPacket(PWINDIVERT_IPHDR ipHdr, PWINDIVERT_TCPHDR tcpHdr);
void RedirectOutBound(std::string filter);
void ValidateHadle(HANDLE handle);
static void SwapAddr(UINT32 *a, UINT32 *b);

// Global Variable.
INT16 PRIORITY = 0;
UINT8 PROXY_ADDR[4];
UINT16 PROXY_PORT;
UINT16 HTTP_PORT;

std::string PROXY_ADDR_STR;
std::string PROXY_PORT_STR;

/*
* Entry.
*/
int __cdecl main(int argc, char **argv)
{
  HANDLE handle, console;
  unsigned char packet[MAXBUF];
  UINT packet_len;
  WINDIVERT_ADDRESS addr;
  PWINDIVERT_IPHDR ip_header;
  PWINDIVERT_TCPHDR tcp_header;
  UINT payload_len;

  std::string proxy_ip_str, proxy_port_str;

  UINT16 modified_src_port = 10000;

  std::map<int, std::tuple<int, UINT32>> record;

  // Check arguments.
  switch (argc)
  {
  case 3:
    proxy_ip_str = std::string(argv[1]);
    proxy_port_str = std::string(argv[2]);
    inet_pton(AF_INET, proxy_ip_str.c_str(), PROXY_ADDR);
    PROXY_PORT = atoi(proxy_port_str.c_str());
    break;
  default:
    fprintf(stderr, "usage: %s [modified_ip] [modified_port]\n", argv[0]);
    fprintf(stderr, "examples:\n");
    fprintf(stderr, "\t%s 10.100.111.139 8080\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // Get console for pretty colors.
  console = GetStdHandle(STD_OUTPUT_HANDLE);

  std::string filter = "((outbound and ip.SrcAddr == 10.100.111.139 and tcp.DstPort == 80) or (inbound and ip.SrcAddr == " + proxy_ip_str + " and tcp.SrcPort == " + proxy_port_str + "))";

  std::cout << "filter : " << filter << std::endl;

  // Divert traffic matching the filter:
  handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, PRIORITY, 0);
  ValidateHadle(handle);

  // Main loop:
  while (TRUE)
  {
    // Read a matching packet.
    if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
    {
      fprintf(stderr, "warning: failed to read packet\n");
      continue;
    }

    WinDivertHelperParsePacket(packet, packet_len, &ip_header,
      NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);

    if (ip_header != NULL && tcp_header != NULL)
    {
      UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
      UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;

      // if Outbound
      if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND) {
        std::cout << "Outbound." << std::endl;

        PrintTitle("origin packet   : ", FOREGROUND_GREEN, console);
        PrintPacket(ip_header, tcp_header);

        record[modified_src_port] = std::make_tuple(ntohs(tcp_header->SrcPort), *(UINT32*)dst_addr);

        ip_header->DstAddr = *(UINT32*)&PROXY_ADDR;
        tcp_header->SrcPort = htons(modified_src_port);
        tcp_header->DstPort = htons(PROXY_PORT);

        modified_src_port++;
        if (modified_src_port >= 65535) {
          modified_src_port = 10000;
        }
      }
      // else if Inbound
      else if (addr.Direction == WINDIVERT_DIRECTION_INBOUND && record.count(ntohs(tcp_header->DstPort)) > 0) {
        std::cout << "Inbound." << std::endl;

        PrintTitle("origin packet   : ", FOREGROUND_GREEN, console);
        PrintPacket(ip_header, tcp_header);

        auto key = ntohs(tcp_header->DstPort);

        ip_header->SrcAddr = std::get<1>(record[key]);
        tcp_header->SrcPort = htons(80);
        tcp_header->DstPort = htons(std::get<0>(record[key]));
        // recv_addr.Direction = !recv_addr.Direction;

        record.erase(key);
      }
      else {
        continue;
      }

      PrintTitle("modified packet : ", FOREGROUND_RED, console);
      PrintPacket(ip_header, tcp_header);

      WinDivertHelperCalcChecksums(packet, packet_len, 0);

      if (!WinDivertSend(handle, packet, packet_len, &addr, NULL)) {
        fprintf(stderr, "\nwarning: failed to send (%d)", GetLastError());
      }

      putchar('\n');
    }
  }
}

void RedirectOutBound(std::string filter) {
  auto handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, PRIORITY, 0);
  ValidateHadle(handle);

  unsigned char packet[MAXBUF];
  UINT packet_len;
  WINDIVERT_ADDRESS addr;
  PWINDIVERT_IPHDR ip_header;
  PWINDIVERT_TCPHDR tcp_header;
  UINT payload_len;

  while (TRUE) {
    if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &payload_len)) {
      fprintf(stderr, "warning: failed to read packet\n");
      continue;
    }
    WinDivertHelperParsePacket(packet, packet_len, &ip_header,
      NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);

    // drop nono tcp/ip packet.
    if (ip_header == NULL || tcp_header == NULL) {
      continue;
    }

    // drop inbound packet.
    if (addr.Direction == WINDIVERT_DIRECTION_INBOUND) {
      continue;
    }

    if (ntohs(tcp_header->DstPort) == HTTP_PORT) {
      SwapAddr(&ip_header->DstAddr, &ip_header->DstAddr);
      tcp_header->DstPort = htons(PROXY_PORT);
      addr.Direction = WINDIVERT_DIRECTION_INBOUND;
    }
    else if (ntohs(tcp_header->SrcPort) == PROXY_PORT) {
      SwapAddr(&ip_header->DstAddr, &ip_header->DstAddr);
      tcp_header->DstPort = htons(HTTP_PORT);
      addr.Direction = WINDIVERT_DIRECTION_INBOUND;
    }
    else {
      continue;
    }

    WinDivertHelperCalcChecksums(packet, packet_len, 0);
    if (!WinDivertSend(handle, packet, payload_len, &addr, NULL)) {
      fprintf(stderr, "\nwarning: failed to send (%d)", GetLastError());
      continue;
    }
  }
}

void ValidateHadle(HANDLE handle) {
  if (handle == INVALID_HANDLE_VALUE)
  {
    if (GetLastError() == ERROR_INVALID_PARAMETER)
    {
      fprintf(stderr, "error: filter syntax error\n");
      exit(EXIT_FAILURE);
    }
    fprintf(stderr, "error: failed to open the WinDivert device (%d)\n", GetLastError());
    exit(EXIT_FAILURE);
  }
}

static void SwapAddr(UINT32 *a, UINT32 *b) {
  UINT32 temp = *a;
  *b = *a;
  *a = temp;
}

static void PrintTitle(std::string msg, int color, HANDLE console) {
  SetConsoleTextAttribute(console, color);
  fputs(msg.c_str(), stdout);
  SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void PrintPacket(PWINDIVERT_IPHDR ipHdr, PWINDIVERT_TCPHDR tcpHdr) {
  UINT8 *src_addr = (UINT8 *)&ipHdr->SrcAddr;
  UINT8 *dst_addr = (UINT8 *)&ipHdr->DstAddr;

  printf("src=%u.%u.%u.%u:%d dst=%u.%u.%u.%u:%d\n",
    src_addr[0], src_addr[1], src_addr[2], src_addr[3], ntohs(tcpHdr->SrcPort),
    dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], ntohs(tcpHdr->DstPort));
}