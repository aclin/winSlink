/*
  Name: pcaplistener.cpp
  Copyright: 2010
  Author: Allan Lin
  Date: 18/07/10 15:33
  Description:
*/

#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#include "pcap.h"
#include "pcaplistener.h"

#define GETBYTE(data,i) (*(((unsigned char *)&data) + i))

pcaplistener::pcaplistener()
{
    getAvailableInterfaces();
}

pcaplistener::~pcaplistener()
{
    /* Object destructed, we don't need any more the device list. Free it */
    pcap_freealldevs(allDevs);
    if (pcap)
    {
	   pcap_close(pcap);
	   pcap = NULL;
	}
}

void pcaplistener::initInterface()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_lookupnet(listenInterface.c_str(), &net, &mask, errbuf))
    {
        fprintf(stderr, "Failed to look up netmask: %s", errbuf);
        exit(0);
    }
    if(!(pcap = pcap_create(listenInterface.c_str(), errbuf)))
    {
        fprintf(stderr, "Failed to create interface source: %s", errbuf);
        exit(0);
    }
    if(pcap_set_snaplen(pcap, SNAPLEN))
    {
        fprintf(stderr, "Failed to set pcap snapshot length: %s", errbuf);
        exit(0);
    }
    if(pcap_set_promisc(pcap, 1))
    {
        fprintf(stderr, "Failed to set interface to promiscuous mode: %s", errbuf);
        exit(0);
    }
    if(pcap_set_timeout(pcap, READ_TIMEOUT_MS))
    {
        fprintf(stderr, "Failed to set pcap timeout: %s", errbuf);
        exit(0);
    }
    if(pcap_activate(pcap))
    {
        fprintf(stderr, "Failed to activate pcap: %s", errbuf);
        exit(0);
    }
    fexpr = "(host 0.0.0.1)";
}

void pcaplistener::getAvailableInterfaces()
{
    pcap_if_t * d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    for(d = allDevs; d != NULL; d = d->next)
    {
        devNames.push_back(string(d->name));
        devDesc.push_back(string(d->description));
    }

    listenInterface = devNames[0];
}

void pcaplistener::listAvailableInterfaces()
{
    int i = 0;
    pcap_if_t * d;

    for(; i<devNames.size(); i++)
    {
        printf("\n%d. %s\n", i+1, devNames[i].c_str());
        printf(" %s\n", devDesc[i].c_str());
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return;
    }
}

void pcaplistener::displaySubnet()
{
    printf("\nSubnet: %u.%u.%u.%u\n", GETBYTE(net, 0), GETBYTE(net,1), GETBYTE(net,2), GETBYTE(net, 3));
}

void pcaplistener::displayNetmask()
{
	printf("\nNetmask: %u.%u.%u.%u\n", GETBYTE(mask, 0), GETBYTE(mask,1), GETBYTE(mask,2), GETBYTE(mask, 3));
}

void pcaplistener::setFilter()
{
    int res;
    struct tm * ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;

    if(pcap_compile(pcap, &filter, fexpr.c_str(), 1, mask) < 0)
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(allDevs);
        exit(0);
    }

    if(pcap_setfilter(pcap, &filter) < 0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(allDevs);
        exit(0);
    }

    printf("Filter is set for %s\n", fexpr.c_str());
    printf("Filtering for packets...\n");

    /* Retrieve the packets */
    /* Using pcap_next_ex() instead of pcap_loop() */
    while((res = pcap_next_ex(pcap, &header, &pkt_data)) >= 0)
    {
        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }

    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(pcap));
        exit(0);
    }

    return;
}
