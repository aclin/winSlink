#ifndef __SLPROXY
#define __SLPROXY

#include "pcaplistener.h"

using namespace std;

class slproxy
{
    public:
        slproxy();
        ~slproxy();

    private:
        pcaplistener pcap;
};

#endif
