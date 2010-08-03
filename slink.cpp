#include <cstdlib>
#include <iostream>
#include <cstdio>

#include "pcap.h"
#include "pcaplistener.h"

using namespace std;

int main(int argc, char *argv[])
{
    //slproxy proxy;
    pcaplistener p;

    p.listAvailableInterfaces();
    p.initInterface();
    p.displaySubnet();
    p.displayNetmask();
    p.setFilter();

    system("PAUSE");
    return EXIT_SUCCESS;
}
