/*
  Issue.
  1. 프록시 서버가 로컬에 있는 경우 정상적으로 리다이렉트되지 않는 문제.
  2. 웹 브라우저에서의 접속은 정상적으로 리다이렉트되나, SnoopSpy의 NetClinet->NetServer 연결이 정상적으로 되지 않는 문제.
*/

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <WS2tcpip.h> // for inet_pton()
#include <iostream>
#include <map>
#include <tuple>

#include "windivert.h"

#define MAXBUF  0xFFFF

typedef std::tuple<UINT32, UINT16> Addr;

/*
* Prototypes.
*/
static void PrintTitle(std::string msg, int color);
static void PrintPacket(PWINDIVERT_IPHDR ipHdr, PWINDIVERT_TCPHDR tcpHdr);
void ValidateHadle(HANDLE handle);

// Global Variable.
HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
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
  HANDLE handle;
  unsigned char packet[MAXBUF];
  UINT pktLen;
  WINDIVERT_ADDRESS addr;
  PWINDIVERT_IPHDR ipHdr;
  PWINDIVERT_TCPHDR tcpHdr;

  std::map<Addr, Addr> history;

  // Check arguments.
  switch (argc)
  {
  case 3:
    PROXY_ADDR_STR = std::string(argv[1]);
    PROXY_PORT_STR = std::string(argv[2]);
    inet_pton(AF_INET, PROXY_ADDR_STR.c_str(), &PROXY_ADDR);
    PROXY_PORT = atoi(PROXY_PORT_STR.c_str());
    break;
  default:
    fprintf(stderr, "usage: %s [proxy_ip] [proxy_port]\n", argv[0]);
    fprintf(stderr, "examples:\n");
    fprintf(stderr, "\t%s 10.100.111.139 8080\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  std::string filter = "((outbound and tcp.DstPort == 80) or (inbound and tcp.SrcPort == " + PROXY_PORT_STR + "))";
  std::cout << "filter : " << filter << std::endl;

  // Divert traffic matching the filter:
  handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, PRIORITY, 0);
  ValidateHadle(handle);

  // Main loop:
  while (TRUE)
  {
    // Read a matching packet.
    if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &pktLen))
    {
      fprintf(stderr, "warning: failed to read packet\n");
      continue;
    }

    WinDivertHelperParsePacket(packet, pktLen, &ipHdr, NULL, NULL, NULL, &tcpHdr, NULL, NULL, NULL);

    if (ipHdr == NULL || tcpHdr == NULL)
    {
      continue;
    }

    if (ntohs(tcpHdr->DstPort) == HTTP_PORT)
    {
      printf(">> Outbound\n");
      PrintTitle("origin packet   : ", FOREGROUND_GREEN);
      PrintPacket(ipHdr, tcpHdr);

      Addr srcAddr(ipHdr->SrcAddr, tcpHdr->SrcPort);
      Addr dstAddr(ipHdr->DstAddr, tcpHdr->DstPort);
      history[srcAddr] = dstAddr;



      ipHdr->DstAddr = PROXY_ADDR;
      tcpHdr->DstPort = htons(PROXY_PORT);

      WinDivertHelperCalcChecksums(packet, pktLen, 0);
      if (!WinDivertSend(handle, packet, pktLen, &addr, NULL))
      {
        std::cout << "Failed to redirect packet." << std::endl;
        std::cerr << "Error Code: " << GetLastError() << std::endl;
      }

      PrintTitle("modified packet : ", FOREGROUND_RED);
      PrintPacket(ipHdr, tcpHdr);
    }
    else if (ntohs(tcpHdr->SrcPort) == PROXY_PORT)
    {
      printf(">> Inbound\n");
      PrintTitle("origin packet   : ", FOREGROUND_GREEN);
      PrintPacket(ipHdr, tcpHdr);

      Addr dstAddr(ipHdr->DstAddr, tcpHdr->DstPort);
      Addr originDstAddr = history[dstAddr];

      std::tie(ipHdr->SrcAddr, tcpHdr->SrcPort) = originDstAddr;

      WinDivertHelperCalcChecksums(packet, pktLen, 0);
      if (!WinDivertSend(handle, packet, pktLen, &addr, NULL))
      {
        std::cout << "Failed to redirect packet." << std::endl;
        std::cerr << "Error Code: " << GetLastError() << std::endl;
      }

      history.erase(dstAddr);

      PrintTitle("modified packet : ", FOREGROUND_RED);
      PrintPacket(ipHdr, tcpHdr);
    }

    printf("\n");
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

static void PrintTitle(std::string msg, int color) {
  SetConsoleTextAttribute(console, color);
  fputs(msg.c_str(), stdout);
  SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void PrintPacket(PWINDIVERT_IPHDR ipHdr, PWINDIVERT_TCPHDR tcpHdr) {
  UINT8 *sa = (UINT8 *)&ipHdr->SrcAddr;
  UINT8 *da = (UINT8 *)&ipHdr->DstAddr;

  printf("src=%u.%u.%u.%u:%d dst=%u.%u.%u.%u:%d\n",
    sa[0], sa[1], sa[2], sa[3], ntohs(tcpHdr->SrcPort),
    da[0], da[1], da[2], da[3], ntohs(tcpHdr->DstPort));
}
