/*
  Name: pcaplistener.h
  Copyright: 2010
  Author: Allan Lin
  Date: 18/07/10 15:31
  Description:
*/

#ifndef __PCAPLISTENER
#define __PCAPLISTENER

#include <cstdlib>
#include <string>
#include <vector>

#include "pcap.h"

#define READ_TIMEOUT_MS 10
#define SNAPLEN 64 * 1024
#define TASK_PACKETS 1

using namespace std;

class pcaplistener
{
    public:
        pcap_t * pcap;
        pcap_if_t * allDevs;
        bpf_u_int32 net;
        bpf_u_int32 mask;
        string listenInterface;
        string fexpr;
        struct bpf_program filter;

        pcaplistener();
        ~pcaplistener();

        void listAvailableInterfaces();
        void initInterface();
        void displaySubnet();
        void displayNetmask();
        void setFilter();

    private:
        vector<string> devNames;
        vector<string> devDesc;

        void getAvailableInterfaces();
};

#endif
