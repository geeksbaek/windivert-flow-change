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

#include "windivert.h"

#define MAXBUF  0xFFFF

struct Addr {
  UINT32 ip;
  UINT16 port;
  
  bool operator<(const Addr &ep) const { return (ip < ep.ip || (ip == ep.ip && port < ep.port)); }
  bool operator==(const Addr &ep) const { return (ip == ep.ip && port == ep.port); }
  bool operator>(const Addr &ep) const { return (ip > ep.ip || (ip == ep.ip && port > ep.port)); }

  Addr() {}
  Addr(UINT32 _ip, USHORT _port) {
    ip = _ip;
    port = _port;
  }
};

/*
* Prototypes.
*/
static void PrintTitle(std::string msg, int color, HANDLE console);
static void PrintPacket(PWINDIVERT_IPHDR ipHdr, PWINDIVERT_TCPHDR tcpHdr);
void ValidateHadle(HANDLE handle);

// Global Variable.
INT16 PRIORITY = 0;
UINT32 PROXY_ADDR;
UINT16 PROXY_PORT;
UINT16 HTTP_PORT = 80;
UINT16 HTTPS_PORT = 443;

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
  PWINDIVERT_IPHDR ipHdr;
  PWINDIVERT_TCPHDR tcpHdr;
  PVOID data = NULL;
  UINT payload_len;

  std::string proxy_ip_str, proxy_port_str;

  UINT16 modified_src_port = 10000;

  std::map<Addr, Addr> client_to_server_map;
  std::map<int, Addr> record;
  std::map<Addr, std::map<UINT32, UINT32>> OutSNMap;
  std::map<Addr, std::map<UINT32, UINT32>> InSNMap;
  std::map<Addr, std::map<UINT32, UINT32>> InOrignalToActualACKMap;

  // Check arguments.
  switch (argc)
  {
  case 3:
    proxy_ip_str = std::string(argv[1]);
    proxy_port_str = std::string(argv[2]);
    inet_pton(AF_INET, proxy_ip_str.c_str(), &PROXY_ADDR);
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

  std::string filter = "((outbound and tcp.DstPort == 80) or (inbound and tcp.SrcPort == " + proxy_port_str + "))";

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

    WinDivertHelperParsePacket(packet, packet_len, &ipHdr,
      NULL, NULL, NULL, &tcpHdr, NULL, &data, &payload_len);

    if (ipHdr == NULL || tcpHdr == NULL)
    {
      continue;
    }

    if (ntohs(tcpHdr->DstPort) == HTTP_PORT) {
      Addr srcAddr(ipHdr->SrcAddr, tcpHdr->SrcPort);
      Addr dstAddr(ipHdr->DstAddr, tcpHdr->DstPort);
      client_to_server_map[srcAddr] = dstAddr;

      ipHdr->DstAddr = PROXY_ADDR;
      tcpHdr->DstPort = htons(PROXY_PORT);

      WinDivertHelperCalcChecksums(packet, packet_len, 0);
      if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
      {
        std::cout << "Failed to redirect packet." << std::endl;
        std::cerr << "Error Code: " << GetLastError() << std::endl;
      }
    } else if (ntohs(tcpHdr->SrcPort) == PROXY_PORT) {
      Addr dstAddr(ipHdr->DstAddr, tcpHdr->DstPort);
      Addr originalDstAddr = client_to_server_map[dstAddr];
      ipHdr->SrcAddr = originalDstAddr.ip;
      tcpHdr->SrcPort = originalDstAddr.port;

      // Modify Response TCP Sequence Number
      if (InSNMap.find(dstAddr) != InSNMap.end())
      {
        UINT32 originalSeqNum = tcpHdr->SeqNum;
        tcpHdr->SeqNum = InSNMap[dstAddr][originalSeqNum];
        std::cout << "SEQ: " << originalSeqNum << " >> " << tcpHdr->SeqNum << std::endl;
        UINT32 nextSeqNum = htonl(ntohl(originalSeqNum) + payload_len);
        InSNMap[dstAddr][nextSeqNum] = htonl(ntohl(tcpHdr->SeqNum) + payload_len);
        InOrignalToActualACKMap[dstAddr][htonl(ntohl(tcpHdr->SeqNum) + payload_len)] = nextSeqNum;
      }
      // Modify Response TCP ACK Number
      if (OutSNMap.find(dstAddr) != OutSNMap.end())
      {
        UINT32 originalACKNum = tcpHdr->AckNum;
        tcpHdr->AckNum = OutSNMap[dstAddr][originalACKNum];
        std::cout << "ACK: " << originalACKNum << " >> " << tcpHdr->AckNum << std::endl;
      }

      WinDivertHelperCalcChecksums(packet, packet_len, 0);
      UINT writeLen;
      if (!WinDivertSend(handle, packet, packet_len, &addr, &writeLen))
      {
        std::cout << "Failed to redirect packet." << std::endl;
        std::cerr << "Error Code: " << GetLastError() << std::endl;
      }

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