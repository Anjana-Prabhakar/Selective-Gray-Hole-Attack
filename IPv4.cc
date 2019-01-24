//
// Copyright (C) 2004 Andras Varga
// Copyright (C) 2014 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include <stdlib.h>
#include <string.h>
#include <map>

//#include <algorithm>

#include "inet/networklayer/ipv4/IPv4.h"

#include "inet/networklayer/arp/ipv4/ARPPacket_m.h"
#include "inet/networklayer/contract/IARP.h"
#include "inet/networklayer/ipv4/ICMPMessage_m.h"
#include "inet/linklayer/common/Ieee802Ctrl.h"
#include "inet/networklayer/ipv4/IIPv4RoutingTable.h"
#include "inet/networklayer/common/IPSocket.h"
#include "inet/networklayer/contract/ipv4/IPv4ControlInfo.h"
#include "inet/networklayer/ipv4/IPv4Datagram.h"
#include "inet/networklayer/ipv4/IPv4InterfaceData.h"
#include "inet/common/lifecycle/NodeOperations.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/LayeredProtocolBase.h"

#include "inet/linklayer/csmaca/CsmaCaMac.h"
#include "inet/routing/aodv/AODVRouting.h"
#include<cmath>

namespace inet {

Define_Module(IPv4);
//@Anjana
static long numForwardedA[5]={0};
static long numForwardedC[5]={0};


long* getUpdateAfromIP()
{

    for(int i=0;i<=4;i++)
        EV<<"inside getUpdateAfromIP. The value of numFwdA is:"<<numForwardedA[i]<<endl;

    return numForwardedA;
}
long* getUpdateCfromIP()
{

    for(int i=0;i<=4;i++)
        EV<<"inside getUpdateCfromIP. The value of numFwdC is:"<<numForwardedC[i]<<endl;

    return numForwardedC;
}

//TODO TRANSLATE
// a multicast cimek eseten hianyoznak bizonyos NetFilter hook-ok
// a local interface-k hasznalata eseten szinten hianyozhatnak bizonyos NetFilter hook-ok

// @Anjana
// ADDED: For malicious stats signals
simsignal_t IPv4::drpPkMaliciousSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::rcvdPkIPV4Signal = SIMSIGNAL_NULL;

simsignal_t IPv4::malStatusSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::malCountSignal = SIMSIGNAL_NULL;

simsignal_t IPv4::detStatusSignal1 = SIMSIGNAL_NULL;
simsignal_t IPv4::detStatusSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::detStatusSignal3 = SIMSIGNAL_NULL;


simsignal_t IPv4::attkSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::possAttkSignal = SIMSIGNAL_NULL;

simsignal_t IPv4::repShSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::repLoSignal = SIMSIGNAL_NULL;

simsignal_t IPv4::fwdCurrSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::monCurrSignal = SIMSIGNAL_NULL;

simsignal_t IPv4::fwdSignal = SIMSIGNAL_NULL;
simsignal_t IPv4::rcvdSignal = SIMSIGNAL_NULL;

simsignal_t IPv4::statSignal1 = SIMSIGNAL_NULL;
simsignal_t IPv4::statSignal2 = SIMSIGNAL_NULL;

simsignal_t IPv4::sentCountSignalA = SIMSIGNAL_NULL;
simsignal_t IPv4::sentCountSignalC = SIMSIGNAL_NULL;
simsignal_t IPv4::rxdCountSignalA = SIMSIGNAL_NULL;
simsignal_t IPv4::rxdCountSignalC = SIMSIGNAL_NULL;






IPv4::IPv4() :
                                                                                                                                                                                                                                                                                                                                                                                isUp(true)
{
}

IPv4::~IPv4()
{
    flush();
    //@Anjana
    delete gatewayUpdateTimer;
    delete networkUpdateTimer;
}

void IPv4::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        QueueBase::initialize();

        ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        rt = getModuleFromPar<IIPv4RoutingTable>(par("routingTableModule"), this);
        arp = getModuleFromPar<IARP>(par("arpModule"), this);
        icmp = getModuleFromPar<ICMP>(par("icmpModule"), this);


        arpInGate = gate("arpIn");
        arpOutGate = gate("arpOut");
        transportInGateBaseId = gateBaseId("transportIn");
        queueOutGateBaseId = gateBaseId("queueOut");

        defaultTimeToLive = par("timeToLive");
        defaultMCTimeToLive = par("multicastTimeToLive");
        fragmentTimeoutTime = par("fragmentTimeout");
        forceBroadcast = par("forceBroadcast");
        useProxyARP = par("useProxyARP");

        curFragmentId = 0;
        lastCheckTime = 0;
        fragbuf.init(icmp);

        numMulticast = numLocalDeliver = numDropped = numUnroutable = numForwarded = 0;
        //numForwardedA=numForwardedC=0;



        flag=5;

        // NetFilter:
        hooks.clear();
        queuedDatagramsForHooks.clear();

        pendingPackets.clear();
        cModule *arpModule = check_and_cast<cModule *>(arp);
        arpModule->subscribe(IARP::completedARPResolutionSignal, this);
        arpModule->subscribe(IARP::failedARPResolutionSignal, this);

        WATCH(numMulticast);
        WATCH(numLocalDeliver);
        WATCH(numDropped);
        WATCH(numUnroutable);
        WATCH(numForwarded);
        WATCH_MAP(pendingPackets);



        //Anjana
        gatewayUpdateTimer = new cMessage("Sending Update to Gateway", GATEWAY_UPDATE);
        networkUpdateTimer = new cMessage("Sending Update to Network", NETWORK_UPDATE);




    }
    else if (stage == INITSTAGE_NETWORK_LAYER) {
        EV<< "inside initstage network layer\n";
        // @Anjana
        // ADDED: For malicious modes
        maliciousState = (int)par("maliciousState");
        maliciousDropProbability = (double)par("maliciousDropProbability");
        // register signals
        rcvdPkIPV4Signal = registerSignal("rcvdPkIPV4");
        drpPkMaliciousSignal = registerSignal("drpPkMalicious");

        malStatusSignal=registerSignal("malStatus");
        malCountSignal=registerSignal("malCount");

        detStatusSignal1=registerSignal("detStatus1");
        detStatusSignal=registerSignal("detStatus");
        detStatusSignal3=registerSignal("detStatus3");

        possAttkSignal=registerSignal("possAttk");
        attkSignal=registerSignal("attack");

        repShSignal=registerSignal("repSh");
        repLoSignal=registerSignal("repLo");

        fwdCurrSignal=registerSignal("fwdCurr");
        monCurrSignal=registerSignal("monCurr");

        fwdSignal=registerSignal("fwd");
        rcvdSignal=registerSignal("rcvd");

        statSignal1=registerSignal("R1stat");
        statSignal2=registerSignal("R2stat");

        sentCountSignalA=registerSignal("sentCountA");
        sentCountSignalC=registerSignal("sentCountC");
        rxdCountSignalA=registerSignal("rxdCountA");
        rxdCountSignalC=registerSignal("rxdCountC");


        // END ADDS
        isUp = isNodeUp();

        //EV<< "checking"<<getUpdate();


    }
}

void IPv4::refreshDisplay() const
{
    char buf[80] = "";
    if (numForwarded > 0)
        sprintf(buf + strlen(buf), "fwd:%d ", numForwarded);
    if (numLocalDeliver > 0)
        sprintf(buf + strlen(buf), "up:%d ", numLocalDeliver);
    if (numMulticast > 0)
        sprintf(buf + strlen(buf), "mcast:%d ", numMulticast);
    if (numDropped > 0)
        sprintf(buf + strlen(buf), "DROP:%d ", numDropped);
    if (numUnroutable > 0)
        sprintf(buf + strlen(buf), "UNROUTABLE:%d ", numUnroutable);
    getDisplayString().setTagArg("t", 0, buf);
}

void IPv4::handleMessage(cMessage *msg)
{
    if (dynamic_cast<RegisterTransportProtocolCommand *>(msg)) {
        RegisterTransportProtocolCommand *command = check_and_cast<RegisterTransportProtocolCommand *>(msg);
        mapping.addProtocolMapping(command->getProtocol(), msg->getArrivalGate()->getIndex());
        delete msg;
        //@Anjana
        IPv4Address nodeIP;

        if (ift->getInterface(0)->ipv4Data() != NULL) {
            nodeIP = ift->getInterface(0)->ipv4Data()->getIPAddress();
        }
        if(nodeIP != IPv4Address("10.0.0.2") && nodeIP != IPv4Address("10.0.0.6") )
        {
            if(!networkUpdateTimer->isScheduled())
            {
                scheduleAt(simTime() + updateIntervalNetwork, networkUpdateTimer);
                EV_INFO << " network timer scheduled\n";
            }
            if(!gatewayUpdateTimer->isScheduled())
            {
                scheduleAt(simTime() + updateIntervalGateway, gatewayUpdateTimer);
                EV_INFO << " gateway timer scheduled\n";
            }

        }

    }

    else if (!msg->isSelfMessage() && msg->getArrivalGate()->isName("arpIn"))
        endService(PK(msg));


    //@Anjana
    else if (msg==gatewayUpdateTimer||msg==networkUpdateTimer)
        //else if (msg==networkUpdateTimer)
    {
        EV_INFO<<"received UpdateTimer message"<<msg<<endl;
        handleTimer(msg);
    }


    //end adds
    else

        QueueBase::handleMessage(msg);
}


//@Anjana
void IPv4::handleTimer(cMessage *timer)
{
    int category=timer->getKind();
    if (category == GATEWAY_UPDATE) {
        EV_INFO << "Sending update to Gateway Event" << std::endl;
        cancelEvent(gatewayUpdateTimer);
        scheduleAt(simTime() + updateIntervalGateway, gatewayUpdateTimer);

        cancelEvent(networkUpdateTimer);
        scheduleAt(simTime() + updateIntervalNetwork, networkUpdateTimer);

        IPv4Address localIP;

        if (ift->getInterface(0)->ipv4Data() != NULL) {
            localIP = ift->getInterface(0)->ipv4Data()->getIPAddress();
        }


        sendUpdateGateway(localIP);
    }

    else
        if (category == NETWORK_UPDATE) {
            EV_INFO << "Sending update to Network Event" << std::endl;
            cancelEvent(networkUpdateTimer);
            scheduleAt(simTime() + updateIntervalNetwork, networkUpdateTimer);

            IPv4Address localIP;

            if (ift->getInterface(0)->ipv4Data() != NULL) {

                localIP = ift->getInterface(0)->ipv4Data()->getIPAddress();
                EV_INFO<<"localIP:"<<localIP<<endl;
            }
            /*int k=ift->getNumInterfaces();
                EV_INFO<<"no: of interfaces are:"<<k<<endl;
                IPv4Address IP1;

                    if (ift->getInterface(0)->ipv4Data() != NULL) {

                                    IP1 = ift->getInterface(0)->ipv4Data()->getIPAddress();
                                }
                    EV_INFO<<"IP1:"<<IP1<<endl;*/

            sendUpdateNetwork(localIP);
        }
        else
            throw cRuntimeError("Invalid timer kind %d", category);


}
//@Anjana
void IPv4::sendUpdateNetwork(IPv4Address localIP)
{
    EV_INFO << "Inside sendUpdate to Network Event" << std::endl;

    IPv4Datagram *datagram=updateNetwork(localIP);

    EV_INFO << "Broadcasting repscore to network\n";


    const InterfaceEntry *broadcastIE;
    broadcastIE = rt->findInterfaceByLocalBroadcastAddress(IPv4Address::ALLONES_ADDRESS);
    //routeLocalBroadcastPacket(datagram, broadcastIE);
    L3Address nextHopAddr(IPv4Address::UNSPECIFIED_ADDRESS);
    if (datagramLocalOutHook(datagram, broadcastIE, nextHopAddr) == INetfilter::IHook::ACCEPT)
        datagramLocalOut(datagram, broadcastIE, nextHopAddr.toIPv4());
    // datagramLocalOut(datagram, broadcastIE, IPv4Address::ALLONES_ADDRESS);
}

void IPv4::sendUpdateGateway(IPv4Address localIP)
{
    EV_INFO << "Inside sendUpdate to Gateway Event" << std::endl;
    IPv4Datagram *datagram=updateGateway(localIP);


    // send to gateway
    EV_INFO << "Forwarding repscore to gateway\n";

    const InterfaceEntry *ie;
    ie = rt->findInterfaceByLocalBroadcastAddress(IPv4Address("10.0.0.2"));

    L3Address nextHopAddr(IPv4Address::UNSPECIFIED_ADDRESS);
    if (datagramLocalOutHook(datagram, ie, nextHopAddr) == INetfilter::IHook::ACCEPT)
        datagramLocalOut(datagram, ie, nextHopAddr.toIPv4());
    // datagramLocalOut(datagram, ie, IPv4Address::ALLONES_ADDRESS);
}

IPv4Datagram *IPv4::updateNetwork(IPv4Address localIP)
{
    EV<< "inside updateNetwork\n";
    int nodeIndexNum=10;
    if(localIP==IPv4Address("10.0.0.1"))
    {

        nodeIndexNum=0;
    }
    else if(localIP==IPv4Address("10.0.0.3"))
    {
        nodeIndexNum=1;
    }
    else if(localIP==IPv4Address("10.0.0.4"))
    {

        nodeIndexNum=2;
    }
    else if(localIP==IPv4Address("10.0.0.5"))
    {

        nodeIndexNum=3;
    }
    else if(localIP==IPv4Address("10.0.0.6"))
    {

        nodeIndexNum=4;
    }
    else if(localIP==IPv4Address("10.0.0.7"))
    {

        nodeIndexNum=5;
    }

    else
        EV_WARN<<"Wrong Address"<<localIP<<endl;

    calculateReputationScoreShort(nodeIndexNum);


    IPv4Datagram *updateNetworkDatagram = createIPv4Datagram("updateNetwork");

    updateNetworkDatagram->setByteLength(IP_HEADER_BYTES);


    // set source and destination address

    updateNetworkDatagram->setSourceAddress(localIP);
    updateNetworkDatagram->setDestAddress(IPv4Address::ALLONES_ADDRESS);

    updateNetworkDatagram->addPar("repShortScore");
    long l=repShort[flag];
    updateNetworkDatagram->par("repShortScore").setLongValue(l);


    // when source address was given, use it; otherwise it'll get the address
    // of the outgoing interface after routing


    // set other fields
    //updateNetworkDatagram->setTypeOfService();

    updateNetworkDatagram->setIdentification(curFragmentId++);
    updateNetworkDatagram->setMoreFragments(false);
    updateNetworkDatagram->setDontFragment(true);
    updateNetworkDatagram->setFragmentOffset(0);

    short ttl = defaultTimeToLive;
    updateNetworkDatagram->setTimeToLive(ttl);
    updateNetworkDatagram->setTransportProtocol(IP_PROT_UDP);

    return updateNetworkDatagram;
}


IPv4Datagram *IPv4::updateGateway(IPv4Address src)
{
    EV<< "inside updateGateway\n";

    //maldrop flag setting

    //pkt count
    if(src==IPv4Address("10.0.0.1")||src==IPv4Address("10.0.0.3"))
    {
        if(countGatewayUpdate!=6)
        {
            countGatewayUpdate++;
        }


        if (countGatewayUpdate==6)
        {
            for(int i =0;i<=1;i++)
            {
                numSentCurrent[i] =numSentDownstream[i]-numSentPast[i];
                numSentPast[i]=numSentDownstream[i];
            }
            emit(sentCountSignalA,numSentCurrent[0]);
            emit(sentCountSignalC,numSentCurrent[1]);
            countGatewayUpdate=0;

        }
    }
    /////

    if(malActivityStatus==1)
    {
        if(gatewayIndex%5==1)
        {

            malStatus[gatewayStatusIndex]=1;
            emit(malStatusSignal,1);
            EV<< "malStatus at"<< gatewayStatusIndex<<"is:"<<malStatus[gatewayStatusIndex]<<endl;
            if(gatewayStatusIndex<25)
                gatewayStatusIndex++;
        }
        emit(malCountSignal,1);
        malActivityStatus=0;
        gatewayIndex++;
    }



    if(attackStat==1)
    {
        emit(attkSignal,1);
        attackStat=0;
    }

    else if(possAttkStat==1)
    {
        emit(possAttkSignal,1);
        possAttkStat=0;
    }

    int nodeIndexNumb=10;
    if(src==IPv4Address("10.0.0.1"))
    {

        nodeIndexNumb=0;
    }
    else if(src==IPv4Address("10.0.0.3"))
    {
        nodeIndexNumb=1;
    }
    else if(src==IPv4Address("10.0.0.4"))
    {

        nodeIndexNumb=2;
    }
    else if(src==IPv4Address("10.0.0.5"))
    {

        nodeIndexNumb=3;
    }
    else if(src==IPv4Address("10.0.0.6"))
    {

        nodeIndexNumb=4;
    }
    else if(src==IPv4Address("10.0.0.7"))
    {

        nodeIndexNumb=5;
    }


    else
        EV_WARN<<"Wrong Address"<<src<<endl;


    int *d=calculateReputationScoreLong(nodeIndexNumb);
    EV<< "value of replong before assignment"<<repLong[0]<<"and"<<repLong[1];
    for (int i=0;i<=1;i++)
    {
        repLong[i]=*(d+i);
    }
    EV<< "value of replong after assignment"<<repLong[0]<<"and"<<repLong[1];

    IPv4Datagram *updateGatewayDatagram = createIPv4Datagram("updateGateway");

    updateGatewayDatagram->setByteLength(IP_HEADER_BYTES);


    // set source and destination address

    updateGatewayDatagram->setSourceAddress(src);
    updateGatewayDatagram->setDestAddress(IPv4Address("10.0.0.2"));

    updateGatewayDatagram->addPar("repLongScoreA");
    updateGatewayDatagram->addPar("repLongScoreC");

    long l1=repLong[0];
    long l2=repLong[1];

    updateGatewayDatagram->par("repLongScoreA").setLongValue(l1);
    updateGatewayDatagram->par("repLongScoreC").setLongValue(l2);

    updateGatewayDatagram->setIdentification(curFragmentId++);
    updateGatewayDatagram->setMoreFragments(false);
    updateGatewayDatagram->setDontFragment(true);
    updateGatewayDatagram->setFragmentOffset(0);

    short ttl = defaultTimeToLive;
    updateGatewayDatagram->setTimeToLive(ttl);
    updateGatewayDatagram->setTransportProtocol(IP_PROT_UDP);

    return updateGatewayDatagram;


}



void IPv4::calculateReputationScoreShort(int nodeIndex)
{
    EV<<"inside calculateReputationScoreShort\n";
    long numFwdDownstreamMonitored[2]={0};
    //long numSentDownstream[2]={0};
    double dropCounter[2]={0};
    //numFwdDownstreamMonitored=inet::getUpdate(nodeIndex);
    long *ptA=inet::getUpdateA();
    numFwdDownstreamMonitored[0]=ptA[nodeIndex];
    long *ptC=inet::getUpdateC();
    numFwdDownstreamMonitored[1]=ptC[nodeIndex];

    EV<<"numFwdDownstreamMonitoredA"<<numFwdDownstreamMonitored[0]<<"and numFwdDownstreamMonitoredC"<<numFwdDownstreamMonitored[1]<<endl;
    int numFwdCurrent[2]={0};
    int numMonitoredCurrent[2]={0};

    /*for (int i=0;i<2;i++)
    {
        numMonitoredCurrent[i]=numFwdDownstreamMonitored[i]-numMonitorPast[i];
        numMonitorPast[i]=numFwdDownstreamMonitored[i];
    }*/
    for (int i=0;i<2;i++)
    {
        numMonitoredCurrent[i]=numFwdDownstreamMonitored[i]-numMonitorPast[count][i];
        numMonitorPast[count][i]=numFwdDownstreamMonitored[i];
    }


    /*numFwdCurrent[0] =numForwardedA[nodeIndex]-numFwdPastA;
    numFwdCurrent[1] =numForwardedC[nodeIndex]-numFwdPastC;*/



    /*int fl0,fl1=1;

if(numForwardedA[nodeIndex] >0 && numForwardedC[nodeIndex]>0)
    {
        fl0=1;
    }
    if(numFwdDownstreamMonitored[0]>0 && numFwdDownstreamMonitored[1]>0)
        {
            fl1=1;
        }


    if(fl0&&fl1)
    { emit(fwdSignal,numFwdTotal);
    if (nodeIndex>=2)
    {
    long *pt=inet::getUpdate();
       numRec=pt[nodeIndex-2];

    }
        for(int i=0;i<=1;i++)
        {


            //if(numFwdCurrent[i]>numMonitoredCurrent[i])
            {
                EV<< "numMonitoredCurrent:"<<i<<":"<<numMonitoredCurrent[i]<<endl;
                EV<< "numFwdCurrent:"<<i<<":"<<numFwdCurrent[i]<<endl;
                // double dropPkt=numForwarded-numFwdDownstreamMonitored;

                if (nodeIndex>=2)
                    {
                    emit(rcvdSignal,numRec);

                    }
                emit(dropSignal0,numFwdCurrent[i]);
                    emit(dropSignal1,numMonitoredCurrent[i]);
                dropCounter[i]=(numFwdCurrent[i]-numMonitoredCurrent[i])/double(numFwdCurrent[i]);
            }
        }
    }
    else
        dropCounter[2]={0};
    EV<< "dropCounter:"<<dropCounter[0]<<"and"<<dropCounter[1]<<endl;*/
    /*emit(dropSignal0,dropCounter[0]);
    emit(dropSignal1,dropCounter[1]);*/

    long *ptSentA=inet::getUpdateSentA();
    long *ptSentC=inet::getUpdateSentC();
    numSentDownstream[0]=ptSentA[nodeIndex];
    numSentDownstream[1]=ptSentC[nodeIndex];

    /*numFwdCurrent[0] =numSentDownstream[0]-numFwdPastA;
    numFwdCurrent[1] =numSentDownstream[1]-numFwdPastC;


    numFwdPastA=numSentDownstream[0];
    numFwdPastC=numSentDownstream[1];*/

    numFwdCurrent[0] =numSentDownstream[0]-numFwdPastA[count];
    numFwdCurrent[1] =numSentDownstream[1]-numFwdPastC[count];

    numFwdPastA[count]=numSentDownstream[0];
    numFwdPastC[count]=numSentDownstream[1];

    //@nkll
    if (count==0)
    {

        count++;

    }
    else if(count==1)
    {
        count--;
    }
    if (nodeIndex>=2)
    {
        long *pt=inet::getUpdate();
        numRec=pt[nodeIndex-2];

    }
    for(int i=0;i<=1;i++)
    {

        EV<< "numMonitoredCurrent:"<<i<<":"<<numMonitoredCurrent[i]<<endl;
        EV<< "numSentCurrent:"<<i<<":"<<numFwdCurrent[i]<<endl;


        if (nodeIndex>=2)
        {
            emit(rcvdSignal,numRec);

        }
        emit(fwdCurrSignal,numFwdCurrent[i]);
        emit(monCurrSignal,numMonitoredCurrent[i]);

        dropCounter[i]=(numFwdCurrent[i]-numMonitoredCurrent[i])/double(numFwdCurrent[i]);
        if(dropCounter[i]<0)
            dropCounter[i]=0;
    }



    EV<< "dropCounter:"<<dropCounter[0]<<"and"<<dropCounter[1]<<endl;


    for(int i=0;i<=1;i++)
    {

        if (dropCounter[i] <= channelLoss)
        {
            EV<< "channelCheck"<<channelCheck[0]<<"and"<<channelCheck[1]<<endl;
            EV<< "normal channel behaviour for"<<i<<endl;
            if(channelCheck[i]==5)
            {
                repFirst[i]= std::max(100,repFirst[i]+sigma);
                //repFirst[i]= std::max(100,repFirst[i]+delta);
                // repFirst[i]= std::min(128,repFirst[i]+delta);
                repFirst[i]= std::min(128,repFirst[i]);
            }
            else
                repFirst[i]= std::min(128,repFirst[i]+sigma);
            if(channelCheck[i]!=5)
                channelCheck[i]++;
        }
        else if (dropCounter[i] <= threshold)
        {
            EV<< "possible attack\n";
            //emit(possAttkSignal,1);
            possAttkStat=1;
            repFirst[i]= std::max(0,repFirst[i]-sigma);
            if(channelCheck[i]!=0)
                channelCheck[i]--;
        }
        else
        {
            EV<< "attack\n";
            attackStat=1;
            //emit(attkSignal,1);
            /*if(channelCheck[i]==0)
                        repFirst[i]= 0;
                    else*/

            repFirst[i]= std::max(0,repFirst[i]-delta);
            if(channelCheck[i]!=0)
                channelCheck[i]--;
        }

        EV<< "repFirst when source is"<<i<<":"<<repFirst[i]<<endl;

    }


    repShort[0]=repFirst[0];
    //repShort[1][2]=localIP.getInt();




    repShort[1]=repFirst[1];
    //repShort[2][2]=localIP.getInt();

    if(nodeIndex==0)
        repShort[1]=500;
    else if(nodeIndex==1)
        repShort[0]=500;

    for (int i=0;i<=1;i++)
        emit(repShSignal,repShort[i]);

    EV<< "repShort[1] new is"<<repShort[1]<<endl;
    EV<< "repShort[0] new is"<<repShort[0]<<endl;

}


int *IPv4::calculateReputationScoreLong(int nodeIndex)
{
    EV<<"inside calculateReputationScoreLong\n";

    // repSecond=  std::max(100,repFirst);
    if(nodeIndex==0)
    {
        repSecond=repShort[0];
        repIntegrated[0]=(si*repShort[0])+ (siBar* repSecond);
        repIntegrated[1]=500;
    }
    else if (nodeIndex==1)
    {
        repSecond=repShort[1];
        repIntegrated[1]=(si*repShort[1])+ (siBar* repSecond);
        repIntegrated[0]=500;
    }
    else if (nodeIndex==2)
    {
        repSecond=repShort[1];
        if(repShort[0]!=0)
            repIntegrated[0]=(si*repShort[0])+ (siBar* repSecond);
        else
            repIntegrated[0]=0;
        if(repShort[1]!=0)
            repIntegrated[1]=(si*repShort[1])+ (siBar* repSecond);
        else
            repIntegrated[1]=0;
    }
    else
    {
        repSecond=(repShort[0]+repShort[1])/2;
        for (int i=0;i<=1;i++)
        {
            if(repShort[i]!=0)

                repIntegrated[i]=(si*repShort[i])+( siBar* repSecond);
            // repIntegrated[i]=repShort[i];
        }
    }

    for (int i=0;i<=1;i++)
    {
        //long term reputation score calculation
        if(repIntegrated[i]!=0 && repIntegrated[i]!=500)
        {
            newR[i]=std::round((si*repLong[i])+(siBar*repIntegrated[i]));
            repLong[i]= std::min(128,newR[i]);//using (1-si) instead of gamma
            repLong[i]=std::max(0,newR[i]);
            emit(repLoSignal,repLong[i]);
        }
        else
        {
            newR[i]=repIntegrated[i];
            repLong[i]=repIntegrated[i];
            emit(repLoSignal,repLong[i]);
        }



    }

    EV<< "repSecond is"<<repSecond<<endl;
    EV<< "repShort is"<<repShort[0]<<"and"<<repShort[1]<<endl;
    EV<<" newR is"<<newR[0]<<"and"<<newR[1]<<endl;
    EV<< "repLong is"<<repLong[0]<<"and"<<repLong[1]<<endl;

    return repLong;
}
//
void IPv4::endService(cPacket *packet)
{
    if (!isUp) {
        EV_ERROR << "IPv4 is down -- discarding message\n";
        delete packet;
        return;
    }
    if (packet->getArrivalGate()->isName("transportIn")) {    //TODO packet->getArrivalGate()->getBaseId() == transportInGateBaseId
        handlePacketFromHL(packet);
    }
    else if (packet->getArrivalGate() == arpInGate) {
        handlePacketFromARP(packet);
    }
    else {    // from network
        EV_INFO << "Received " << packet << " from network.\n";

        const InterfaceEntry *fromIE = getSourceInterfaceFrom(packet);
        if (auto arpPacket = dynamic_cast<ARPPacket *>(packet))
            handleIncomingARPPacket(arpPacket, fromIE);
        else if (auto dgram = dynamic_cast<IPv4Datagram *>(packet))
        {
            //numrec++;
            handleIncomingDatagram(dgram, fromIE);
        }
        else
            throw cRuntimeError(packet, "Unexpected packet type");
    }
}

const InterfaceEntry *IPv4::getSourceInterfaceFrom(cPacket *packet)
{
    cGate *g = packet->getArrivalGate();
    return g ? ift->getInterfaceByNetworkLayerGateIndex(g->getIndex()) : nullptr;
}

void IPv4::handleIncomingDatagram(IPv4Datagram *datagram, const InterfaceEntry *fromIE)
{
    ASSERT(datagram);
    ASSERT(fromIE);
    emit(LayeredProtocolBase::packetReceivedFromLowerSignal, datagram);

    //
    // "Prerouting"
    //
    //std::cout<<datagram->getSrcAddress();

    // check for header biterror
    if (datagram->hasBitError()) {
        // probability of bit error in header = size of header / size of total message
        // (ignore bit error if in payload)
        double relativeHeaderLength = datagram->getHeaderLength() / (double)datagram->getByteLength();
        if (dblrand() <= relativeHeaderLength) {
            EV_WARN << "bit error found, sending ICMP_PARAMETER_PROBLEM\n";
            icmp->sendErrorMessage(datagram, fromIE->getInterfaceId(), ICMP_PARAMETER_PROBLEM, 0);
            return;
        }

    }

    // hop counter decrement
    datagram->setTimeToLive(datagram->getTimeToLive() - 1);

    EV_DETAIL << "Received datagram `" << datagram->getName() << "' with dest=" << datagram->getDestAddress() << "\n";
    IPv4Address src=datagram->getSourceAddress().toIPv4();
    if(src==IPv4Address("10.0.0.1"))
    {
        numRxd[0]++;
    }
    else if(src==IPv4Address("10.0.0.3"))
    {
        numRxd[1]++;
    }

    const InterfaceEntry *destIE = nullptr;
    L3Address nextHop(IPv4Address::UNSPECIFIED_ADDRESS);
    if (datagramPreRoutingHook(datagram, fromIE, destIE, nextHop) == INetfilter::IHook::ACCEPT)
        preroutingFinish(datagram, fromIE, destIE, nextHop.toIPv4());
}

void IPv4::detectAttack(int nodeIndex)
{
    EV_INFO<<"Inside detection algo for node :"<<nodeIndex<<endl;
    EV<<"updateMatrix[nodeIndex][0]"<<updateMatrix[nodeIndex][0]<<endl;
    EV<<"updateMatrix[nodeIndex][1]"<<updateMatrix[nodeIndex][1]<<endl;
    double dev=0;
    double d1=0;
    double d2=0;
    double d3=0;
    /////////////////
    if (nodeIndex==0)
    {

        //if(updateMatrix[nodeIndex][0] + updateMatrix[nodeIndex][2] !=0)
        if(updateMatrix[nodeIndex][0] !=0)
            //avgRep[nodeIndex]=(updateMatrix[nodeIndex][0]+(8*updateMatrix[nodeIndex][2]))/9;
            avgRep[nodeIndex]=(updateMatrix[nodeIndex][0]+updateMatrix[1][1])/2;
        updateMatrix[nodeIndex][2]=avgRep[nodeIndex];
        deviation[0]=updateMatrix[nodeIndex][0]-avgRep[nodeIndex];
        deviation[1]=updateMatrix[nodeIndex][1];
        deviation[2]=updateMatrix[nodeIndex][2]-avgRep[nodeIndex];//other nodes
        d1=std::abs(deviation[0]);
        d2=std::abs(deviation[2]);
        if(d1+d2!=0)

        {
            dev=(pow(d1,2.0)+(8*pow(d2,2.0)))/9.0;
            EV<<"inside node:"<<nodeIndex<<endl;
        }
    }
    else if (nodeIndex==1)
    {

        //if(updateMatrix[nodeIndex][2] +updateMatrix[nodeIndex][1]!=0)
        if(updateMatrix[nodeIndex][1]!=0)
            // avgRep[nodeIndex]=(updateMatrix[nodeIndex][1]+(8*updateMatrix[nodeIndex][2]))/9;
            avgRep[nodeIndex]=(updateMatrix[nodeIndex][1]+updateMatrix[0][0])/2;
        updateMatrix[nodeIndex][2]= avgRep[nodeIndex];
        deviation[0]=updateMatrix[nodeIndex][0];
        deviation[1]=updateMatrix[nodeIndex][1]-avgRep[nodeIndex];
        deviation[2]=updateMatrix[nodeIndex][2]-avgRep[nodeIndex];//other nodes
        d1=std::abs(deviation[1]);
        d2=std::abs(deviation[2]);
        if(d1+d2!=0)

        {
            dev=(pow(d1,2.0)+(8*pow(d2,2.0)))/9.0;
            EV<<"inside node:"<<nodeIndex<<endl;
        }
    }
    ////////////
    /*   if (nodeIndex==0)
    {
        updateMatrix[nodeIndex][2]=updateMatrix[1][1];
        //if(updateMatrix[nodeIndex][0] + updateMatrix[nodeIndex][2] !=0)
        if(updateMatrix[nodeIndex][0] !=0)
            avgRep[nodeIndex]=(updateMatrix[nodeIndex][0]+(8*updateMatrix[nodeIndex][2]))/9;
        //avgRep[nodeIndex]=(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1])/2;
        deviation[0]=updateMatrix[nodeIndex][0]-avgRep[nodeIndex];
        deviation[1]=updateMatrix[nodeIndex][1];
        deviation[2]=updateMatrix[nodeIndex][2]-avgRep[nodeIndex];//other nodes
        d1=std::abs(deviation[0]);
        d2=std::abs(deviation[2]);
        if(d1+d2!=0)

        {
            dev=(pow(d1,2.0)+(8*pow(d2,2.0)))/9.0;
            EV<<"inside node:"<<nodeIndex<<endl;
        }
    }
    else if (nodeIndex==1)
    {
        updateMatrix[nodeIndex][2]=updateMatrix[0][0];
        //if(updateMatrix[nodeIndex][2] +updateMatrix[nodeIndex][1]!=0)
        if(updateMatrix[nodeIndex][1]!=0)
            avgRep[nodeIndex]=(updateMatrix[nodeIndex][1]+(8*updateMatrix[nodeIndex][2]))/9;
        deviation[0]=updateMatrix[nodeIndex][0];
        deviation[1]=updateMatrix[nodeIndex][1]-avgRep[nodeIndex];
        deviation[2]=updateMatrix[nodeIndex][2]-avgRep[nodeIndex];//other nodes
        d1=std::abs(deviation[1]);
        d2=std::abs(deviation[2]);
        if(d1+d2!=0)

        {
            dev=(pow(d1,2.0)+(8*pow(d2,2.0)))/9.0;
            EV<<"inside node:"<<nodeIndex<<endl;
        }
    } */
    else if (nodeIndex==2)
    {
        //considering SGHA in single flow

        updateMatrix[nodeIndex][2]=updateMatrix[nodeIndex][1];
        //updateMatrix[nodeIndex][2]=updateMatrix[nodeIndex][1];

        //considering SGHA in multiple flows
        //updateMatrix[nodeIndex][2]=(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1])/2;
        //updateMatrix[nodeIndex][2]=80;
        if(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1]!=0)
            avgRep[nodeIndex]=(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1]+(8*updateMatrix[nodeIndex][2]))/10;
        //avgRep[nodeIndex]=(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1]+(8*updateMatrix[nodeIndex][2]))/10;
        //avgRep[nodeIndex]=0.5*(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1]);

        //updateMatrix[nodeIndex][2]=avgRep[nodeIndex];
        deviation[0]=updateMatrix[nodeIndex][0]-avgRep[nodeIndex];
        deviation[1]=updateMatrix[nodeIndex][1]-avgRep[nodeIndex];
        deviation[2]=updateMatrix[nodeIndex][2]-avgRep[nodeIndex];//other nodes
        d1=std::abs(deviation[0]);
        d2=std::abs(deviation[1]);
        d3=std::abs(deviation[2]);
        if(d1+d2!=0)
        {
            dev=(pow(d1,2.0)+pow(d2,2.0)+(8*pow(d3,2.0)))/10.0;
            // dev=(pow(d1,2.0)+pow(d2,2.0))/2.0;
            EV<<"inside node:"<<nodeIndex<<"and"<<dev<<endl;
            //dev=0;
        }
    }

    else if (nodeIndex>=3)
    {
        updateMatrix[nodeIndex][2]=0;
        if(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1]!=0)
            avgRep[nodeIndex]=0.5*(updateMatrix[nodeIndex][0]+updateMatrix[nodeIndex][1]);
        deviation[0]=updateMatrix[nodeIndex][0]-avgRep[nodeIndex];
        deviation[1]=updateMatrix[nodeIndex][1]-avgRep[nodeIndex];
        deviation[2]=0;//other nodes
        d1=std::abs(deviation[0]);
        d2=std::abs(deviation[1]);
        if(d1+d2!=0)
            dev=(pow(d1,2.0)+pow(d2,2.0))/2.0;

    }



    deviationTotal=sqrt(dev);



    EV_INFO<<"dev:"<<dev<<endl;
    EV_INFO<<"deviation[0]:"<<deviation[0]<<endl;
    EV_INFO<<"deviation[1]:"<<deviation[1]<<endl;
    EV_INFO<<"deviation[2]:"<<deviation[2]<<endl;
    EV_INFO<<"deviationTotal:"<<deviationTotal<<endl;
    //deviationTotal=5;
    if (deviationTotal<=dmax)
    {
        if(avgRep[nodeIndex]>=attackRep)
        {
            if(nodeIndex==0)
            {
                EV_INFO<<"R4 is normal\n";
                statusR4[itR4]=0;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }

            }
            else if(nodeIndex==1)
            {
                EV_INFO<<"R4 is normal\n";
                statusR4[itR4]=0;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }

            }
            else if(nodeIndex==2)
            {
                EV_INFO<<"R2 is normal\n";
                statusR2[itR2]=0;
                emit(statSignal2,1);
                if(itR2!=4)
                {
                    itR2++;
                }
                else
                {
                    itR2=0;
                }
            }
            else if(nodeIndex==3)
            {
                EV_INFO<<"R3 is normal\n";
                statusR3[itR3]=0;
                //emit(statSig3,1);
                if(itR3!=4)
                {
                    itR3++;
                }
                else
                {
                    itR3=0;
                }
            }

            else if(nodeIndex==5)
            {
                EV_INFO<<"R1 is normal\n";
                statusR1[itR1]=0;
                emit(statSignal1,1);
                if(itR1!=4)
                {
                    itR1++;
                }
                else
                {
                    itR1=0;
                }
            }
            else
                EV_INFO<<"error\n";
        }
        else
        {
            if(nodeIndex==0)
            {
                EV_INFO<<"R4 is malicious-SFA\n";
                statusR4[itR4]=1;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }
                //emit(sfaStatusSignal1,1);

            }
            else if(nodeIndex==1)
            {
                EV_INFO<<"R4 is malicious-SFA\n";
                statusR4[itR4]=1;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }
            }
            else if(nodeIndex==2)
            {
                EV_INFO<<"R2 is malicious-SFA\n";
                statusR2[itR2]=1;
                if(itR2!=4)
                {
                    itR2++;
                }
                else
                {
                    itR2=0;
                }
                emit(statSignal2,2);
            }
            else if(nodeIndex==3)
            {
                EV_INFO<<"R3 is malicious-SFA\n";
                statusR3[itR3]=1;
                if(itR3!=4)
                {
                    itR3++;
                }
                else
                {
                    itR3=0;
                }
            }
            else if(nodeIndex==5)
            {
                EV_INFO<<"R1 is malicious-SFA\n";
                statusR1[itR1]=1;
                if(itR1!=4)
                {
                    itR1++;
                }
                else
                {
                    itR1=0;
                }
                emit(statSignal1,2);
            }

            else
                EV_INFO<<"error\n";
        }
    }
    else
    {
        int min=(std::abs(deviation[0]));
        int max=std::abs(deviation[0]);


        for (int i = 1; i <= 2; i++)
        {
            if (std::abs(deviation[i]) > max)
            {
                max = std::abs(deviation[i]);
                in_max=i;
            }
            else if (std::abs(deviation[i]) < min)
            {
                min = std::abs(deviation[i]);
                in_min=i;
            }
        }


        if(max==500)
        {
            for(int i=0;i<=2;i++)
            {
                if(i!=in_max && i!=in_min)
                {
                    max=std::abs(deviation[i]);
                    in_max=i;
                }
            }
        }


        if(deviation[in_max]>0 && deviation[2]<0)
        {

            if(nodeIndex==0)
                EV_INFO<<"A is trying a promotion attack when source is"<<in_max<<endl;
            else if(nodeIndex==1)
                EV_INFO<<"C is trying a promotion attack when source is"<<in_max<<endl;
            else if(nodeIndex==2)
            {
                EV_INFO<<"R1 is trying a promotion attack when source is"<<in_max<<endl;
                statusR1[itR1]=2;

                emit(statSignal1,3);

                if( itR1!=4)
                {
                    itR1++;
                    EV_INFO<<"itR1 is now"<<itR1<<endl;
                }
                else
                    itR1=0;

            }
            else if(nodeIndex==3)
            {
                EV_INFO<<"R2 is trying a promotion attack when source is"<<in_max<<endl;
                statusR2[itR2]=2;

                emit(statSignal2,3);
                if( itR2!=4)
                {

                    itR2++;
                    EV_INFO<<"itR2 is now"<<itR2<<endl;
                }
                else
                    itR2=0;


            }
            else if(nodeIndex==4)
            {
                EV_INFO<<"R3 is trying a promotion attack when source is"<<in_max<<endl;
                statusR3[itR3]=2;

                if( itR3 !=4)
                {
                    itR3++;
                    EV_INFO<<"itR3 is now"<<itR3<<endl;
                }
                else
                    itR3=0;
            }
            else if(nodeIndex==5)
            {
                EV_INFO<<"R4 is trying a promotion attack when source is"<<in_max<<endl;
                statusR4[itR4]=2;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }
            }
            else
            {
                EV_INFO<<"error\n";
            }
        }
        /* if(deviation[in_max]>0 && std::abs(deviation[in_max])==std::abs(deviation[in_min]))
        {
            if(nodeIndex==2)
            {

                emit(statSignal1,1);

            }
            else if(nodeIndex==3)
            {

                emit(statSignal2,1);

            }
            else if(nodeIndex==4)
            {
                EV_INFO<<"R3 is normal"<<in_max<<endl;

            }
            else if(nodeIndex==5)
                        {
                            EV_INFO<<"R4 is normal"<<in_max<<endl;

                        }
        }
         */
        //////////////////
        int ck=0;
        attackRep=80;
        for (int i=0;i<=1;i++)
        {
            if((updateMatrix[nodeIndex][i]<attackRep && deviation[i]<0)||(deviation[i]>0 && updateMatrix[nodeIndex][2]<attackRep))
            {
                ck=1;
            }
        }
        if(ck==1)
        {
            //////////////////////////////////////
            /* else if(updateMatrix[nodeIndex][in_max]<attackRep)
        {*/
            if(nodeIndex==0)
            {
                EV_INFO<<"R4 is trying a SGHA attack when source is"<<in_max<<endl;
                statusR4[itR4]=3;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }
            }
            else if(nodeIndex==1)
            {
                EV_INFO<<"R4 is trying a SGHA attack when source is"<<in_max<<endl;
                statusR4[itR4]=3;
                if(itR4!=4)
                {
                    itR4++;
                }
                else
                {
                    itR4=0;
                }
            }
            else if(nodeIndex==2)
            {
                EV_INFO<<"R2 is trying a SGHA attack when source is"<<in_max<<endl;
                statusR2[itR2]=3;
                if( itR2!=4)
                {
                    EV_INFO<<"itR2 is now"<<itR2<<endl;
                    itR2++;

                }
                else
                    itR2=0;

                emit(statSignal2,4);
            }
            else if(nodeIndex==3)
            {
                EV_INFO<<"R3 is trying a SGHA attack when source is"<<in_max<<endl;
                statusR3[itR3]=3;
                if(  itR3 !=4)
                {
                    itR3++;
                }
                else
                    itR3=0;


            }
            else if(nodeIndex==5)
            {
                EV_INFO<<"R1 is trying a SGHA attack when source is"<<in_max<<endl;
                statusR1[itR1]=3;

                if( itR1!=4)
                {
                    itR1++;
                }
                else
                    itR1=0;


                emit(statSignal1,4);
            }

            else
                EV_INFO<<"error\n";
        }
        else
        {
            //complete for rest of the nodes
            if(nodeIndex==2)
            {
                emit(statSignal2,1);
                statusR2[itR2]=0;
                if( itR2!=4)
                {
                    EV_INFO<<"itR2 is now"<<itR2<<endl;
                    itR2++;

                }
                else
                    itR2=0;
            }

        }


    }


    if(itR1==0 && nodeIndex==5)
    {
        // create and fill the map
        std::map< int, int > occurances;
        for ( int i = 0; i < 5; ++i )
        {
            ++occurances[ statusR1[i] ];
            EV<<"statusR1"<<statusR1[i]<< '\n';
        }



        std::cout << "Greatest: " << occurances.rbegin()->first << '\n';
        EV_INFO<<"Greatest: "<<occurances.rbegin()->first<<endl;
        feedbackScore=(int)occurances.rbegin()->first;

        // print the contents of the map
        using iterator = std::map< int, int >::iterator;
        for ( iterator iter = occurances.begin(); iter != occurances.end(); ++iter )
        {
            std::cout << iter->first << ": " << iter->second << '\n';
            EV_INFO<<iter->first << ": " << iter->second << '\n';

        }

    }
    else if (itR2==0 && nodeIndex==2)
    {
        // create and fill the map
        std::map< int, int > occurances;
        for ( int i = 0; i < 5; ++i )
        {
            ++occurances[ statusR2[i] ];
            EV<<"statusR2"<<statusR2[i]<< '\n';
        }

        std::cout << "Greatest: " << occurances.rbegin()->first << '\n';
        EV_INFO<<"Greatest: "<<occurances.rbegin()->first<<endl;
        feedbackScore=(int)occurances.rbegin()->first;

        // print the contents of the map
        using iterator = std::map< int, int >::iterator;
        for ( iterator iter = occurances.begin(); iter != occurances.end(); ++iter )
        {
            EV_INFO<<"inside iterator" <<endl;
            std::cout << iter->first << ": " << iter->second << '\n';
            EV_INFO<<iter->first << ": " << iter->second << '\n';

        }
        for(int i=0;i<=1;i++)
        {
            EV_INFO<<"calculating num rxd";
            numRxdCurrent[i]=numRxd[i]-numRxdPast[i];
            numRxdPast[i]=numRxd[i];
            EV_INFO<<numRxdCurrent[i] << endl;


        }
        emit(rxdCountSignalA,numRxdCurrent[0]);
        emit(rxdCountSignalC,numRxdCurrent[1]);


        sendFeedback(feedbackScore,in_max,nodeIndex, numRxdCurrent[in_max]);
        /*if(feedbackScore==3)
                 {


                 }*/

    }
    else if (itR3==0 && nodeIndex==3)
    {
        // create and fill the map
        std::map< int, int > occurances;
        for ( int i = 0; i < 5; ++i )
        {
            ++occurances[ statusR3[i] ];
            EV<<"statusR3"<<statusR3[i]<< '\n';
        }

        std::cout << "Greatest: " << occurances.rbegin()->first << '\n';
        EV_INFO<<"Greatest: "<<occurances.rbegin()->first<<endl;
        feedbackScore=(int)occurances.rbegin()->first;

        // print the contents of the map
        using iterator = std::map< int, int >::iterator;
        for ( iterator iter = occurances.begin(); iter != occurances.end(); ++iter )
        {
            std::cout << iter->first << ": " << iter->second << '\n';
            EV_INFO<<iter->first << ": " << iter->second << '\n';

        }


    }
    else if (itR4==0 && nodeIndex==1)
    {
        // create and fill the map
        std::map< int, int > occurances;
        for ( int i = 0; i < 5; ++i )
        {
            ++occurances[ statusR4[i] ];
            EV<<"statusR4"<<statusR4[i]<< '\n';
        }

        std::cout << "Greatest: " << occurances.rbegin()->first << '\n';
        EV_INFO<<"Greatest: "<<occurances.rbegin()->first<<endl;
        feedbackScore=(int)occurances.rbegin()->first;

        // print the contents of the map
        using iterator = std::map< int, int >::iterator;
        for ( iterator iter = occurances.begin(); iter != occurances.end(); ++iter )
        {
            std::cout << iter->first << ": " << iter->second << '\n';
            EV_INFO<<iter->first << ": " << iter->second << '\n';
        }

    }

    return;
}
IPv4Datagram *IPv4::sendFeedback(int feedbackScore,int in_max,int nodeIndex,int numRxdCurr)
{
    EV_INFO << "Inside sendFeedback" << std::endl;
    //change
    IPv4Datagram *sendFeedbackDatagram = createIPv4Datagram("sendFeedback");

    sendFeedbackDatagram->setByteLength(IP_HEADER_BYTES);


    // set source and destination address

    sendFeedbackDatagram->setSourceAddress(IPv4Address("10.0.0.2"));
    if(nodeIndex==2 && in_max==0)
        sendFeedbackDatagram->setDestAddress(IPv4Address("10.0.0.1"));
    else if(nodeIndex==2 && in_max==1)
        sendFeedbackDatagram->setDestAddress(IPv4Address("10.0.0.3"));

    sendFeedbackDatagram->addPar("feedbackScore");
    sendFeedbackDatagram->addPar("in_max");
    sendFeedbackDatagram->addPar("numRxdCurr");

    long l1=feedbackScore;
    long l2=in_max;
    long l3=numRxdCurr;

    sendFeedbackDatagram->par("feedbackScore").setLongValue(l1);
    sendFeedbackDatagram->par("in_max").setLongValue(l2);
    sendFeedbackDatagram->par("numRxdCurr").setLongValue(l3);

    sendFeedbackDatagram->setIdentification(curFragmentId++);
    sendFeedbackDatagram->setMoreFragments(false);
    sendFeedbackDatagram->setDontFragment(true);
    sendFeedbackDatagram->setFragmentOffset(0);

    short ttl = defaultTimeToLive;
    sendFeedbackDatagram->setTimeToLive(ttl);

    sendFeedbackDatagram->setTransportProtocol(IP_PROT_UDP);


    // send to gateway
    EV_INFO << "Forwarding feedback to node\n";

    const InterfaceEntry *ie;
    ie = rt->findInterfaceByLocalBroadcastAddress(IPv4Address(sendFeedbackDatagram->getDestinationAddress().toIPv4()));

    L3Address nextHopAddr(IPv4Address::UNSPECIFIED_ADDRESS);
    if (datagramLocalOutHook(sendFeedbackDatagram, ie, nextHopAddr) == INetfilter::IHook::ACCEPT)
        datagramLocalOut(sendFeedbackDatagram, ie, nextHopAddr.toIPv4());
    // datagramLocalOut(datagram, ie, IPv4Address::ALLONES_ADDRESS);
}
void IPv4::preroutingFinish(IPv4Datagram *datagram, const InterfaceEntry *fromIE, const InterfaceEntry *destIE, IPv4Address nextHopAddr)
{
    IPv4Address& destAddr = datagram->getDestAddress();



    // remove control info
    delete datagram->removeControlInfo();

    // route packet

    if (fromIE->isLoopback()) {
        reassembleAndDeliver(datagram);
    }
    else if (destAddr.isMulticast()) {
        // check for local delivery
        // Note: multicast routers will receive IGMP datagrams even if their interface is not joined to the group
        if (fromIE->ipv4Data()->isMemberOfMulticastGroup(destAddr) ||
                (rt->isMulticastForwardingEnabled() && datagram->getTransportProtocol() == IP_PROT_IGMP))
            reassembleAndDeliver(datagram->dup());
        else
            EV_WARN << "Skip local delivery of multicast datagram (input interface not in multicast group)\n";

        // don't forward if IP forwarding is off, or if dest address is link-scope
        if (!rt->isMulticastForwardingEnabled()) {
            EV_WARN << "Skip forwarding of multicast datagram (forwarding disabled)\n";
            delete datagram;
        }
        else if (destAddr.isLinkLocalMulticast()) {
            EV_WARN << "Skip forwarding of multicast datagram (packet is link-local)\n";
            delete datagram;
        }
        else if (datagram->getTimeToLive() == 0) {
            EV_WARN << "Skip forwarding of multicast datagram (TTL reached 0)\n";
            delete datagram;
        }
        else

            forwardMulticastPacket(datagram, fromIE);
    }
    else
    {

        EV<<"Entering error zone\n";
        EV<<"destAddr:"<<destAddr<<endl;
        EV<<"isLocalAddress:"<<rt->isLocalAddress(destAddr)<<endl;
        // check for local delivery; we must accept also packets coming from the interfaces that
        // do not yet have an IP address assigned. This happens during DHCP requests.

        if (fromIE->ipv4Data()->getIPAddress().isUnspecified() ||rt->isLocalAddress(destAddr) )
        {
            //@Anjana
            if(datagram->hasPar("repLongScoreA"))
            {
                IPv4Address src=datagram->getSourceAddress().toIPv4();
                if(src==IPv4Address("10.0.0.1"))
                {
                    updateMatrix[0][0]=datagram->par("repLongScoreA").longValue();
                    updateMatrix[0][1]=datagram->par("repLongScoreC").longValue();
                    EV_INFO<<"Receiving repLongScore"<< updateMatrix[0][0]<<"and"<< updateMatrix[0][1]<<"from A"<< endl;
                    nodeIndex=0;
                }
                else if(src==IPv4Address("10.0.0.3"))
                {
                    updateMatrix[1][0]=datagram->par("repLongScoreA").longValue();
                    updateMatrix[1][1]=datagram->par("repLongScoreC").longValue();
                    EV_INFO<<"Receiving repLongScore"<< updateMatrix[1][0]<<"and"<< updateMatrix[1][1]<<"from C"<< endl;
                    nodeIndex=1;
                }
                else if(src==IPv4Address("10.0.0.4"))
                {
                    updateMatrix[2][0]=datagram->par("repLongScoreA").longValue();
                    updateMatrix[2][1]=datagram->par("repLongScoreC").longValue();
                    EV_INFO<<"Receiving repLongScore"<< updateMatrix[2][0]<<"and"<< updateMatrix[2][1]<<"from R1"<< endl;
                    nodeIndex=2;
                }
                else if(src==IPv4Address("10.0.0.5"))
                {
                    updateMatrix[3][0]=datagram->par("repLongScoreA").longValue();
                    updateMatrix[3][1]=datagram->par("repLongScoreC").longValue();
                    EV_INFO<<"Receiving repLongScore"<< updateMatrix[3][0]<<"and"<< updateMatrix[3][1]<<"from R2"<< endl;
                    nodeIndex=3;
                }
                else if(src==IPv4Address("10.0.0.6"))
                {
                    updateMatrix[4][0]=datagram->par("repLongScoreA").longValue();
                    updateMatrix[4][1]=datagram->par("repLongScoreC").longValue();
                    EV_INFO<<"Receiving repLongScore"<< updateMatrix[4][0]<<"and"<< updateMatrix[4][1]<<"from R3"<< endl;
                    nodeIndex=4;
                }
                //extra node
                else if(src==IPv4Address("10.0.0.7"))
                {
                    updateMatrix[5][0]=datagram->par("repLongScoreA").longValue();
                    updateMatrix[5][1]=datagram->par("repLongScoreC").longValue();
                    EV_INFO<<"Receiving repLongScore"<< updateMatrix[5][0]<<"and"<< updateMatrix[5][1]<<"from R4"<< endl;
                    nodeIndex=5;
                }


                else
                {
                    EV_INFO<<"Wrong Address"<<src<<datagram->par("repLongScoreA").longValue()<<datagram->par("repLongScoreC").longValue()<<endl;
                }
                detectAttack(nodeIndex);
                delete datagram;
                return;
            }

            reassembleAndDeliver(datagram);
        }
        else if (destAddr.isLimitedBroadcastAddress() || (destIE = rt->findInterfaceByLocalBroadcastAddress(destAddr)))
        {
            //@Anjana
            const InterfaceEntry* broadcastIE = rt->findInterfaceByLocalBroadcastAddress(destAddr);
            if(datagram->hasPar("repShortScore"))
            {
                long repSecondRxd=datagram->par("repShortScore").longValue();
                EV_INFO<<"Receiving repsecond"<<repSecond<<endl;
                delete datagram;
                return;

            }
            // broadcast datagram on the target subnet if we are a router
            if (broadcastIE && fromIE != broadcastIE && rt->isForwardingEnabled())
                fragmentPostRouting(datagram->dup(), broadcastIE, IPv4Address::ALLONES_ADDRESS);

            EV_INFO << "Broadcast received\n";
            reassembleAndDeliver(datagram);
        }
        else if (!rt->isForwardingEnabled())
        {
            EV_WARN << "forwarding off, dropping packet\n";
            numDropped++;

            emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
            delete datagram;
        }

        // @Anjana ADDED: For malicious modes
        // Why put it here?  This method handles non control traffic (stuff we don't wanna drop)
        // These packets eventually end up at some recipient (unless we be all malicious and drop them
        // or something outside our control to prevent the packet from reaching its destination).
        // This mode will drop packets randomly according to the probability given
        else{
            //@Anjana
            EV_INFO << "class name-1\n";
            EV <<datagram->getClassName()<<endl;

            flag=1;
            if(datagram->getSourceAddress()==IPv4Address("10.0.0.1"))
            {
                flag=0;
            }


            if (maliciousState == 1 && flag==0 )
            {
                EV << "it's a packet from A :\n";

                emit(rcvdPkIPV4Signal, datagram);

                // dblrand() is a OMNeT++ function which returns a random number in [0, 1)
                if((1.0 - maliciousDropProbability) <= dblrand())
                {
                    malActivityStatus=1;
                    emit(drpPkMaliciousSignal, datagram);

                    EV << "[maliciousState = 1] Packet Dropped\n";
                    numDropped++;
                    delete datagram;  // keeps OMNeT++ happy
                    return;

                }

                // END ADDS
                routeUnicastPacket(datagram, fromIE, destIE, nextHopAddr);
            }
            else

                routeUnicastPacket(datagram, fromIE, destIE, nextHopAddr);

        }
    }
}




void IPv4::handleIncomingARPPacket(ARPPacket *packet, const InterfaceEntry *fromIE)
{
    // give it to the ARP module
    IMACProtocolControlInfo *ctrl = check_and_cast<IMACProtocolControlInfo *>(packet->getControlInfo());
    ctrl->setInterfaceId(fromIE->getInterfaceId());
    EV_INFO << "Sending " << packet << " to arp.\n";
    send(packet, arpOutGate);
}

void IPv4::handleIncomingICMP(ICMPMessage *packet)
{
    switch (packet->getType()) {
    case ICMP_REDIRECT:    // TODO implement redirect handling
    case ICMP_DESTINATION_UNREACHABLE:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETER_PROBLEM: {
        // ICMP errors are delivered to the appropriate higher layer protocol
        IPv4Datagram *bogusPacket = check_and_cast<IPv4Datagram *>(packet->getEncapsulatedPacket());
        int protocol = bogusPacket->getTransportProtocol();
        int gateindex = mapping.getOutputGateForProtocol(protocol);
        send(packet, "transportOut", gateindex);
        emit(LayeredProtocolBase::packetSentToUpperSignal, packet);
        break;
    }

    default: {
        // all others are delivered to ICMP: ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY,
        // ICMP_TIMESTAMP_REQUEST, ICMP_TIMESTAMP_REPLY, etc.
        int gateindex = mapping.getOutputGateForProtocol(IP_PROT_ICMP);
        send(packet, "transportOut", gateindex);
        emit(LayeredProtocolBase::packetSentToUpperSignal, packet);
        break;
    }
    }
}

void IPv4::handlePacketFromHL(cPacket *packet)
{
    EV_INFO << "Received " << packet << " from upper layer.\n";
    emit(LayeredProtocolBase::packetReceivedFromUpperSignal, packet);

    // if no interface exists, do not send datagram
    if (ift->getNumInterfaces() == 0) {
        EV_ERROR << "No interfaces exist, dropping packet\n";
        numDropped++;
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, packet);
        delete packet;
        return;
    }

    // encapsulate
    IPv4ControlInfo *controlInfo = check_and_cast<IPv4ControlInfo *>(packet->removeControlInfo());
    //@Anjana
    IPv4Address src=controlInfo->getSourceAddress().toIPv4();
    if(src==IPv4Address("10.0.0.1"))
    {
        controlInfo->setDiffServCodePoint(10);

    }
    else if(src==IPv4Address("10.0.0.3"))
    {
        controlInfo->setDiffServCodePoint(30);

    }
    else
        controlInfo->setDiffServCodePoint(0);
    //end addn
    IPv4Datagram *datagram = encapsulate(packet, controlInfo);

    // extract requested interface and next hop
    const InterfaceEntry *destIE = controlInfo ? const_cast<const InterfaceEntry *>(ift->getInterfaceById(controlInfo->getInterfaceId())) : nullptr;

    if (controlInfo)
        datagram->setControlInfo(controlInfo); //FIXME ne rakjuk bele a cntrInfot!!!!! de kell :( kulonben a hook queue-ban elveszik a multicastloop flag


    L3Address nextHopAddr(IPv4Address::UNSPECIFIED_ADDRESS);
    if (datagramLocalOutHook(datagram, destIE, nextHopAddr) == INetfilter::IHook::ACCEPT)
        datagramLocalOut(datagram, destIE, nextHopAddr.toIPv4());
}

void IPv4::handlePacketFromARP(cPacket *packet)
{
    EV_INFO << "Received " << packet << " from arp.\n";
    // send out packet on the appropriate interface
    IMACProtocolControlInfo *ctrl = check_and_cast<IMACProtocolControlInfo *>(packet->getControlInfo());
    InterfaceEntry *destIE = ift->getInterfaceById(ctrl->getInterfaceId());
    sendPacketToNIC(packet, destIE);
}

void IPv4::datagramLocalOut(IPv4Datagram *datagram, const InterfaceEntry *destIE, IPv4Address requestedNextHopAddress)
{
    IPv4ControlInfo *controlInfo = check_and_cast_nullable<IPv4ControlInfo *>(datagram->removeControlInfo());
    bool multicastLoop = true;
    if (controlInfo != nullptr) {
        multicastLoop = controlInfo->getMulticastLoop();
        delete controlInfo;
    }

    // send
    IPv4Address& destAddr = datagram->getDestAddress();


    EV_DETAIL << "Sending datagram " << datagram << " with destination = " << destAddr << "and Source address as"<<datagram->getSourceAddress()<< "\n";

    if (datagram->getDestAddress().isMulticast()) {
        destIE = determineOutgoingInterfaceForMulticastDatagram(datagram, destIE);

        // loop back a copy
        if (multicastLoop && (!destIE || !destIE->isLoopback())) {
            const InterfaceEntry *loopbackIF = ift->getFirstLoopbackInterface();
            if (loopbackIF)
                fragmentPostRouting(datagram->dup(), loopbackIF, destAddr);
        }

        if (destIE) {
            numMulticast++;
            fragmentPostRouting(datagram, destIE, destAddr);
        }
        else {
            EV_ERROR << "No multicast interface, packet dropped\n";
            numUnroutable++;
            emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
            delete datagram;
        }
    }
    else {    // unicast and broadcast
        // check for local delivery
        if (rt->isLocalAddress(destAddr)) {
            EV_INFO << "Delivering " << datagram << " locally.\n";
            if (destIE && !destIE->isLoopback()) {
                EV_DETAIL << "datagram destination address is local, ignoring destination interface specified in the control info\n";
                destIE = nullptr;
            }
            if (!destIE)
                destIE = ift->getFirstLoopbackInterface();
            ASSERT(destIE);
            routeUnicastPacket(datagram, nullptr, destIE, destAddr);
        }
        else if (destAddr.isLimitedBroadcastAddress() || rt->isLocalBroadcastAddress(destAddr))
            routeLocalBroadcastPacket(datagram, destIE);
        else
            routeUnicastPacket(datagram, nullptr, destIE, requestedNextHopAddress);

    }
}

/* Choose the outgoing interface for the muticast datagram:
 *   1. use the interface specified by MULTICAST_IF socket option (received in the control info)
 *   2. lookup the destination address in the routing table
 *   3. if no route, choose the interface according to the source address
 *   4. or if the source address is unspecified, choose the first MULTICAST interface
 */
const InterfaceEntry *IPv4::determineOutgoingInterfaceForMulticastDatagram(IPv4Datagram *datagram, const InterfaceEntry *multicastIFOption)
{
    const InterfaceEntry *ie = nullptr;
    if (multicastIFOption) {
        ie = multicastIFOption;
        EV_DETAIL << "multicast packet routed by socket option via output interface " << ie->getName() << "\n";
    }
    if (!ie) {
        IPv4Route *route = rt->findBestMatchingRoute(datagram->getDestAddress());
        if (route)
            ie = route->getInterface();
        if (ie)
            EV_DETAIL << "multicast packet routed by routing table via output interface " << ie->getName() << "\n";
    }
    if (!ie) {
        ie = rt->getInterfaceByAddress(datagram->getSrcAddress());
        if (ie)
            EV_DETAIL << "multicast packet routed by source address via output interface " << ie->getName() << "\n";
    }
    if (!ie) {
        ie = ift->getFirstMulticastInterface();
        if (ie)
            EV_DETAIL << "multicast packet routed via the first multicast interface " << ie->getName() << "\n";
    }
    return ie;
}

void IPv4::routeUnicastPacket(IPv4Datagram *datagram, const InterfaceEntry *fromIE, const InterfaceEntry *destIE, IPv4Address requestedNextHopAddress)
{

    IPv4Address destAddr = datagram->getDestAddress();

    EV_INFO << "Routing " << datagram << " with destination = " << destAddr << ", ";

    IPv4Address nextHopAddr;
    // if output port was explicitly requested, use that, otherwise use IPv4 routing
    if (destIE) {
        EV_DETAIL << "using manually specified output interface " << destIE->getName() << "\n";
        // and nextHopAddr remains unspecified
        if (!requestedNextHopAddress.isUnspecified())
            nextHopAddr = requestedNextHopAddress;
        // special case ICMP reply
        else if (destIE->isBroadcast()) {
            // if the interface is broadcast we must search the next hop
            const IPv4Route *re = rt->findBestMatchingRoute(destAddr);
            if (re && re->getInterface() == destIE)
                nextHopAddr = re->getGateway();
        }
    }
    else {
        // use IPv4 routing (lookup in routing table)
        const IPv4Route *re = rt->findBestMatchingRoute(destAddr);
        if (re) {
            destIE = re->getInterface();
            nextHopAddr = re->getGateway();
        }
    }

    if (!destIE) {    // no route found
        EV_WARN << "unroutable, sending ICMP_DESTINATION_UNREACHABLE, dropping packet\n";
        numUnroutable++;
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
        icmp->sendErrorMessage(datagram, fromIE ? fromIE->getInterfaceId() : -1, ICMP_DESTINATION_UNREACHABLE, 0);
    }
    else {    // fragment and send
        L3Address nextHop(nextHopAddr);
        if (fromIE != nullptr) {
            if (datagramForwardHook(datagram, fromIE, destIE, nextHop) != INetfilter::IHook::ACCEPT)
                return;
            nextHopAddr = nextHop.toIPv4();
        }

        routeUnicastPacketFinish(datagram, fromIE, destIE, nextHopAddr);
    }
}

void IPv4::routeUnicastPacketFinish(IPv4Datagram *datagram, const InterfaceEntry *fromIE, const InterfaceEntry *destIE, IPv4Address nextHopAddr)
{
    EV_INFO << "output interface = " << destIE->getName() << ", next hop address = " << nextHopAddr << "\n";
    numForwarded++;

    //@Anjana
    numFwdTotal++;
    IPv4Address src=datagram->getSourceAddress().toIPv4();
    EV_INFO<<"Source address is"<<src;
    IPv4Address localIP;

    if (ift->getInterface(0)->ipv4Data() != NULL) {

        localIP = ift->getInterface(0)->ipv4Data()->getIPAddress();
        EV_INFO<<"current node:"<<localIP<<endl;
    }

    if(src==IPv4Address("10.0.0.1"))
    {


        EV_INFO<<"num forwarded from A ";
        if(localIP==IPv4Address("10.0.0.1"))
        {

            numForwardedA[0]++;


            EV_INFO<<"at A:"<<numForwardedA[0]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.3"))
        {
            numForwardedA[1]++;

            EV_INFO<<"at C:"<<numForwardedA[1]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.4"))
        {
            numForwardedA[2]++;

            EV_INFO<<"at R1:"<<numForwardedA[2]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.5"))
        {
            numForwardedA[3]++;

            EV_INFO<<"at R2:"<<numForwardedA[3]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.6"))
        {
            numForwardedA[4]++;

            EV_INFO<<"at R3:"<<numForwardedA[4]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.7"))
        {
            numForwardedA[5]++;

            EV_INFO<<"at R4:"<<numForwardedA[5]<<endl;
        }


        else
            EV_WARN<<"wrong node address"<<localIP<<endl;
    }


    else if(src==IPv4Address("10.0.0.3"))
    {

        EV_INFO<<"num forwarded from C ";
        if(localIP==IPv4Address("10.0.0.1"))
        {

            numForwardedC[0]++;

            EV_INFO<<"at A:"<<numForwardedC[0]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.3"))
        {
            numForwardedC[1]++;

            EV_INFO<<"at C:"<<numForwardedC[1]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.4"))
        {
            numForwardedC[2]++;

            EV_INFO<<"at R1:"<<numForwardedC[2]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.5"))
        {
            numForwardedC[3]++;

            EV_INFO<<"at R2:"<<numForwardedC[3]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.6"))
        {
            numForwardedC[4]++;

            EV_INFO<<"at R3:"<<numForwardedC[4]<<endl;
        }
        else if(localIP==IPv4Address("10.0.0.7"))
        {
            numForwardedC[5]++;

            EV_INFO<<"at R4:"<<numForwardedC[5]<<endl;
        }



        else
            EV_WARN<<"wrong local address"<<localIP<<endl;
    }
    else
        EV_WARN<<"wrong src address"<<src<<endl;

    //end addn


    fragmentPostRouting(datagram, destIE, nextHopAddr);

}

void IPv4::routeLocalBroadcastPacket(IPv4Datagram *datagram, const InterfaceEntry *destIE)
{
    // The destination address is 255.255.255.255 or local subnet broadcast address.
    // We always use 255.255.255.255 as nextHopAddress, because it is recognized by ARP,
    // and mapped to the broadcast MAC address.
    EV_INFO<<"inside routelocal\n";
    if (destIE != nullptr) {
        EV_INFO<<"inside routelocal-1\n";
        fragmentPostRouting(datagram, destIE, IPv4Address::ALLONES_ADDRESS);
    }
    else if (forceBroadcast) {
        EV_INFO<<"inside routelocal-2\n";
        // forward to each interface including loopback
        for (int i = 0; i < ift->getNumInterfaces(); i++) {
            const InterfaceEntry *ie = ift->getInterface(i);
            fragmentPostRouting(datagram->dup(), ie, IPv4Address::ALLONES_ADDRESS);
        }
        delete datagram;
    }
    else {
        EV_INFO<<"inside routelocal-3"<<datagram <<"and"<<datagram->getName()<<endl;
        int cmp=strcmp(datagram->getName(),"updateNetwork");
        if(datagram->getDestinationAddress()==IPv4Address::ALLONES_ADDRESS && cmp==0)
        {
            EV_INFO<<"inside routelocal-4\n";
            // forward to each interface including loopback
            // for (int i = 0; i < ift->getNumInterfaces(); i++) {
            const InterfaceEntry *ie = ift->getInterface(0);
            EV_INFO<<"inside routelocal-5"<<ie<<endl;
            fragmentPostRouting(datagram->dup(), ie, IPv4Address::ALLONES_ADDRESS);
            //}
            delete datagram;

        }
        else
        {
            numDropped++;
            emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
            delete datagram;
        }
    }
}

const InterfaceEntry *IPv4::getShortestPathInterfaceToSource(IPv4Datagram *datagram)
{
    return rt->getInterfaceForDestAddr(datagram->getSrcAddress());
}

void IPv4::forwardMulticastPacket(IPv4Datagram *datagram, const InterfaceEntry *fromIE)
{
    ASSERT(fromIE);
    const IPv4Address& srcAddr = datagram->getSrcAddress();
    const IPv4Address& destAddr = datagram->getDestAddress();
    ASSERT(destAddr.isMulticast());
    ASSERT(!destAddr.isLinkLocalMulticast());

    EV_INFO << "Forwarding multicast datagram `" << datagram->getName() << "' with dest=" << destAddr << "\n";

    numMulticast++;

    const IPv4MulticastRoute *route = rt->findBestMatchingMulticastRoute(srcAddr, destAddr);
    if (!route) {
        EV_WARN << "Multicast route does not exist, try to add.\n";
        emit(NF_IPv4_NEW_MULTICAST, datagram);

        // read new record
        route = rt->findBestMatchingMulticastRoute(srcAddr, destAddr);

        if (!route) {
            EV_ERROR << "No route, packet dropped.\n";
            numUnroutable++;
            emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
            delete datagram;
            return;
        }
    }

    if (route->getInInterface() && fromIE != route->getInInterface()->getInterface()) {
        EV_ERROR << "Did not arrive on input interface, packet dropped.\n";
        emit(NF_IPv4_DATA_ON_NONRPF, datagram);
        numDropped++;
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
        delete datagram;
    }
    // backward compatible: no parent means shortest path interface to source (RPB routing)
    else if (!route->getInInterface() && fromIE != getShortestPathInterfaceToSource(datagram)) {
        EV_ERROR << "Did not arrive on shortest path, packet dropped.\n";
        numDropped++;
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
        delete datagram;
    }
    else {
        emit(NF_IPv4_DATA_ON_RPF, datagram);    // forwarding hook

        numForwarded++;

        // copy original datagram for multiple destinations
        for (unsigned int i = 0; i < route->getNumOutInterfaces(); i++) {
            IPv4MulticastRoute::OutInterface *outInterface = route->getOutInterface(i);
            const InterfaceEntry *destIE = outInterface->getInterface();
            if (destIE != fromIE && outInterface->isEnabled()) {
                int ttlThreshold = destIE->ipv4Data()->getMulticastTtlThreshold();
                if (datagram->getTimeToLive() <= ttlThreshold)
                    EV_WARN << "Not forwarding to " << destIE->getName() << " (ttl treshold reached)\n";
                else if (outInterface->isLeaf() && !destIE->ipv4Data()->hasMulticastListener(destAddr))
                    EV_WARN << "Not forwarding to " << destIE->getName() << " (no listeners)\n";
                else {
                    EV_DETAIL << "Forwarding to " << destIE->getName() << "\n";
                    fragmentPostRouting(datagram->dup(), destIE, destAddr);
                }
            }
        }

        emit(NF_IPv4_MDATA_REGISTER, datagram);    // postRouting hook

        // only copies sent, delete original datagram
        delete datagram;
    }
}

void IPv4::reassembleAndDeliver(IPv4Datagram *datagram)
{
    EV_INFO << "Delivering " << datagram << " locally.\n";

    if (datagram->getSrcAddress().isUnspecified())
        EV_WARN << "Received datagram '" << datagram->getName() << "' without source address filled in\n";

    // reassemble the packet (if fragmented)
    if (datagram->getFragmentOffset() != 0 || datagram->getMoreFragments()) {
        EV_DETAIL << "Datagram fragment: offset=" << datagram->getFragmentOffset()
                                                                                                                                                                                                                                                                                                                                                                                              << ", MORE=" << (datagram->getMoreFragments() ? "true" : "false") << ".\n";

        // erase timed out fragments in fragmentation buffer; check every 10 seconds max
        if (simTime() >= lastCheckTime + 10) {
            lastCheckTime = simTime();
            fragbuf.purgeStaleFragments(simTime() - fragmentTimeoutTime);
        }

        datagram = fragbuf.addFragment(datagram, simTime());
        if (!datagram) {
            EV_DETAIL << "No complete datagram yet.\n";
            return;
        }
        EV_DETAIL << "This fragment completes the datagram.\n";
    }

    if (datagramLocalInHook(datagram, getSourceInterfaceFrom(datagram)) != INetfilter::IHook::ACCEPT) {
        return;
    }

    reassembleAndDeliverFinish(datagram);
}

void IPv4::reassembleAndDeliverFinish(IPv4Datagram *datagram)
{
    // decapsulate and send on appropriate output gate
    int protocol = datagram->getTransportProtocol();
    EV_INFO<<"The transp protocol is:"<<protocol<<endl;
    if (protocol == IP_PROT_ICMP) {
        // incoming ICMP packets are handled specially
        handleIncomingICMP(check_and_cast<ICMPMessage *>(decapsulate(datagram)));
        numLocalDeliver++;
    }
    else if (protocol == IP_PROT_IP) {
        // tunnelled IP packets are handled separately
        send(decapsulate(datagram), "preRoutingOut");    //FIXME There is no "preRoutingOut" gate in the IPv4 module.
    }
    else {
        int gateindex = mapping.findOutputGateForProtocol(protocol);
        // check if the transportOut port are connected, otherwise discard the packet
        if (gateindex >= 0) {
            cGate *outGate = gate("transportOut", gateindex);
            if (outGate->isPathOK()) {
                cPacket *packet = decapsulate(datagram);
                //@Anjana
                if(packet!=nullptr)
                {
                    send(packet, outGate);
                    emit(LayeredProtocolBase::packetSentToUpperSignal, packet);
                    numLocalDeliver++;
                }
                else
                    EV_INFO<<"Packet is empty\n";
                return;
            }
        }

        EV_ERROR << "Transport protocol ID=" << protocol << " not connected, discarding packet\n";
        int inputInterfaceId = getSourceInterfaceFrom(datagram)->getInterfaceId();
        icmp->sendErrorMessage(datagram, inputInterfaceId, ICMP_DESTINATION_UNREACHABLE, ICMP_DU_PROTOCOL_UNREACHABLE);
    }
}

cPacket *IPv4::decapsulate(IPv4Datagram *datagram)
{
    // decapsulate transport packet
    const InterfaceEntry *fromIE = getSourceInterfaceFrom(datagram);

    cPacket *packet = datagram->decapsulate();
    //@Anjana
    if(packet!=nullptr)

    {
        IPv4ControlInfo *controlInfo;

        // create and fill in control info
        controlInfo = new IPv4ControlInfo();

        controlInfo->setProtocol(datagram->getTransportProtocol());
        controlInfo->setSrcAddr(datagram->getSrcAddress());
        controlInfo->setDestAddr(datagram->getDestAddress());
        controlInfo->setTypeOfService(datagram->getTypeOfService());
        controlInfo->setInterfaceId(fromIE ? fromIE->getInterfaceId() : -1);
        controlInfo->setTimeToLive(datagram->getTimeToLive());

        // original IPv4 datagram might be needed in upper layers to send back ICMP error message
        controlInfo->setOrigDatagram(datagram);

        // attach control info


        packet->setControlInfo(controlInfo);
    }
    return packet;

}

void IPv4::fragmentPostRouting(IPv4Datagram *datagram, const InterfaceEntry *ie, IPv4Address nextHopAddr)
{
    L3Address nextHop(nextHopAddr);
    if (datagramPostRoutingHook(datagram, getSourceInterfaceFrom(datagram), ie, nextHop) == INetfilter::IHook::ACCEPT)
    {EV_INFO<<"inside fragmentpostrouting\n";
    fragmentAndSend(datagram, ie, nextHop.toIPv4());
    }
}

void IPv4::fragmentAndSend(IPv4Datagram *datagram, const InterfaceEntry *ie, IPv4Address nextHopAddr)
{
    // fill in source address
    if (datagram->getSrcAddress().isUnspecified())
        datagram->setSrcAddress(ie->ipv4Data()->getIPAddress());

    // hop counter check
    if (datagram->getTimeToLive() <= 0) {
        // drop datagram, destruction responsibility in ICMP
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
        EV_WARN << "datagram TTL reached zero, sending ICMP_TIME_EXCEEDED\n";
        icmp->sendErrorMessage(datagram, -1    /*TODO*/, ICMP_TIME_EXCEEDED, 0);
        numDropped++;
        return;
    }

    int mtu = ie->getMTU();
    EV_INFO<<"inside fragmentandSend"<<mtu<<endl;
    // send datagram straight out if it doesn't require fragmentation (note: mtu==0 means infinite mtu)
    if (mtu == 0 || datagram->getByteLength() <= mtu) {
        sendDatagramToOutput(datagram, ie, nextHopAddr);
        return;
    }

    // if "don't fragment" bit is set, throw datagram away and send ICMP error message
    if (datagram->getDontFragment()) {
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, datagram);
        EV_WARN << "datagram larger than MTU and don't fragment bit set, sending ICMP_DESTINATION_UNREACHABLE\n";
        icmp->sendErrorMessage(datagram, -1    /*TODO*/, ICMP_DESTINATION_UNREACHABLE,
                ICMP_DU_FRAGMENTATION_NEEDED);
        numDropped++;
        return;
    }

    // FIXME some IP options should not be copied into each fragment, check their COPY bit
    int headerLength = datagram->getHeaderLength();
    int payloadLength = datagram->getByteLength() - headerLength;
    int fragmentLength = ((mtu - headerLength) / 8) * 8;    // payload only (without header)
    int offsetBase = datagram->getFragmentOffset();
    if (fragmentLength <= 0)
        throw cRuntimeError("Cannot fragment datagram: MTU=%d too small for header size (%d bytes)", mtu, headerLength); // exception and not ICMP because this is likely a simulation configuration error, not something one wants to simulate

    int noOfFragments = (payloadLength + fragmentLength - 1) / fragmentLength;
    EV_DETAIL << "Breaking datagram into " << noOfFragments << " fragments\n";

    // create and send fragments
    std::string fragMsgName = datagram->getName();
    fragMsgName += "-frag";

    for (int offset = 0; offset < payloadLength; offset += fragmentLength) {
        bool lastFragment = (offset + fragmentLength >= payloadLength);
        // length equal to fragmentLength, except for last fragment;
        int thisFragmentLength = lastFragment ? payloadLength - offset : fragmentLength;

        // FIXME is it ok that full encapsulated packet travels in every datagram fragment?
        // should better travel in the last fragment only. Cf. with reassembly code!
        IPv4Datagram *fragment = datagram->dup();
        fragment->setName(fragMsgName.c_str());

        // "more fragments" bit is unchanged in the last fragment, otherwise true
        if (!lastFragment)
            fragment->setMoreFragments(true);

        fragment->setByteLength(headerLength + thisFragmentLength);
        fragment->setFragmentOffset(offsetBase + offset);

        sendDatagramToOutput(fragment, ie, nextHopAddr);
    }

    delete datagram;
}

IPv4Datagram *IPv4::encapsulate(cPacket *transportPacket, IPv4ControlInfo *controlInfo)
{
    IPv4Datagram *datagram = createIPv4Datagram(transportPacket->getName());
    datagram->setByteLength(IP_HEADER_BYTES);
    datagram->encapsulate(transportPacket);

    // set source and destination address
    IPv4Address dest = controlInfo->getDestAddr();
    EV_INFO<<"dest="<<dest<<endl;
    datagram->setDestAddress(dest);

    IPv4Address src = controlInfo->getSrcAddr();
    EV_INFO<<"src="<<src<<endl;
    // when source address was given, use it; otherwise it'll get the address
    // of the outgoing interface after routing
    if (!src.isUnspecified()) {
        // if interface parameter does not match existing interface, do not send datagram
        if (rt->getInterfaceByAddress(src) == nullptr)
            throw cRuntimeError("Wrong source address %s in (%s)%s: no interface with such address",
                    src.str().c_str(), transportPacket->getClassName(), transportPacket->getFullName());

        datagram->setSrcAddress(src);
    }

    // set other fields
    datagram->setTypeOfService(controlInfo->getTypeOfService());
    EV_INFO<<"TypeOfService()="<<controlInfo->getTypeOfService()<<endl;
    datagram->setIdentification(curFragmentId++);
    EV_INFO<<"Identification="<<curFragmentId<<endl;
    datagram->setMoreFragments(false);
    datagram->setDontFragment(controlInfo->getDontFragment());
    datagram->setFragmentOffset(0);

    //@Anjana

    short ttl;
    if (controlInfo->getTimeToLive() > 0)
        ttl = controlInfo->getTimeToLive();
    else if (datagram->getDestAddress().isLinkLocalMulticast())
        ttl = 1;
    else if (datagram->getDestAddress().isMulticast())
        ttl = defaultMCTimeToLive;
    else
        ttl = defaultTimeToLive;
    datagram->setTimeToLive(ttl);
    datagram->setTransportProtocol(controlInfo->getProtocol());
    EV_INFO<<"TransportProtocol="<<controlInfo->getProtocol()<<endl;
    // setting IPv4 options is currently not supported

    return datagram;
}

IPv4Datagram *IPv4::createIPv4Datagram(const char *name)
{
    return new IPv4Datagram(name);
}

void IPv4::sendDatagramToOutput(IPv4Datagram *datagram, const InterfaceEntry *ie, IPv4Address nextHopAddr)
{
    {
        bool isIeee802Lan = ie->isBroadcast() && !ie->getMacAddress().isUnspecified();    // we only need/can do ARP on IEEE 802 LANs
        if (!isIeee802Lan) {

            sendPacketToNIC(datagram, ie);
        }
        else {
            if (nextHopAddr.isUnspecified()) {
                IPv4InterfaceData *ipv4Data = ie->ipv4Data();
                IPv4Address destAddress = datagram->getDestAddress();
                if (IPv4Address::maskedAddrAreEqual(destAddress, ie->ipv4Data()->getIPAddress(), ipv4Data->getNetmask()))
                    nextHopAddr = destAddress;
                else if (useProxyARP) {
                    nextHopAddr = destAddress;
                    EV_WARN << "no next-hop address, using destination address " << nextHopAddr << " (proxy ARP)\n";
                }
                else {
                    throw cRuntimeError(datagram, "Cannot send datagram on broadcast interface: no next-hop address and Proxy ARP is disabled");
                }
            }

            MACAddress nextHopMacAddr;    // unspecified
            nextHopMacAddr = resolveNextHopMacAddress(datagram, nextHopAddr, ie);

            if (nextHopMacAddr.isUnspecified()) {
                EV_INFO << "Pending " << datagram << " to ARP resolution.\n";
                pendingPackets[nextHopAddr].insert(datagram);
            }
            else {
                ASSERT2(pendingPackets.find(nextHopAddr) == pendingPackets.end(), "IPv4-ARP error: nextHopAddr found in ARP table, but IPv4 queue for nextHopAddr not empty");
                sendPacketToIeee802NIC(datagram, ie, nextHopMacAddr, ETHERTYPE_IPv4);
            }
        }
    }
}

void IPv4::arpResolutionCompleted(IARP::Notification *entry)
{
    if (entry->l3Address.getType() != L3Address::IPv4)
        return;
    auto it = pendingPackets.find(entry->l3Address.toIPv4());
    if (it != pendingPackets.end()) {
        cPacketQueue& packetQueue = it->second;
        EV << "ARP resolution completed for " << entry->l3Address << ". Sending " << packetQueue.getLength()
                                                                                                                                                                                                                                                                                                                                                                                       << " waiting packets from the queue\n";

        while (!packetQueue.isEmpty()) {
            cPacket *msg = packetQueue.pop();
            EV << "Sending out queued packet " << msg << "\n";
            sendPacketToIeee802NIC(msg, entry->ie, entry->macAddress, ETHERTYPE_IPv4);
        }
        pendingPackets.erase(it);
    }
}

void IPv4::arpResolutionTimedOut(IARP::Notification *entry)
{
    if (entry->l3Address.getType() != L3Address::IPv4)
        return;
    auto it = pendingPackets.find(entry->l3Address.toIPv4());
    if (it != pendingPackets.end()) {
        cPacketQueue& packetQueue = it->second;
        EV << "ARP resolution failed for " << entry->l3Address << ",  dropping " << packetQueue.getLength() << " packets\n";
        for (int i = 0; i < packetQueue.getLength(); i++) {
            auto packet = packetQueue.get(i);
            emit(LayeredProtocolBase::packetFromUpperDroppedSignal, packet);
        }
        packetQueue.clear();
        pendingPackets.erase(it);
    }
}

MACAddress IPv4::resolveNextHopMacAddress(cPacket *packet, IPv4Address nextHopAddr, const InterfaceEntry *destIE)
{
    if (nextHopAddr.isLimitedBroadcastAddress() || nextHopAddr == destIE->ipv4Data()->getNetworkBroadcastAddress()) {
        EV_DETAIL << "destination address is broadcast, sending packet to broadcast MAC address\n";
        return MACAddress::BROADCAST_ADDRESS;
    }

    if (nextHopAddr.isMulticast()) {
        MACAddress macAddr = MACAddress::makeMulticastAddress(nextHopAddr);
        EV_DETAIL << "destination address is multicast, sending packet to MAC address " << macAddr << "\n";
        return macAddr;
    }

    return arp->resolveL3Address(nextHopAddr, destIE);
}

void IPv4::sendPacketToIeee802NIC(cPacket *packet, const InterfaceEntry *ie, const MACAddress& macAddress, int etherType)
{

    // remove old control info
    delete packet->removeControlInfo();

    // add control info with MAC address
    Ieee802Ctrl *controlInfo = new Ieee802Ctrl();
    controlInfo->setDest(macAddress);
    controlInfo->setEtherType(etherType);

    packet->setControlInfo(controlInfo);

    sendPacketToNIC(packet, ie);
}

void IPv4::sendPacketToNIC(cPacket *packet, const InterfaceEntry *ie)
{

    EV_INFO << "Sending " << packet << " to output interface = " << ie->getName() << ".\n";
    //EV_DEBUG << "packet has the origincode " <<check_and_cast<IPv4Datagram *>(packet)->getDiffServCodePoint();
    send(packet, queueOutGateBaseId + ie->getNetworkLayerGateIndex());
}

// NetFilter:

void IPv4::registerHook(int priority, INetfilter::IHook *hook)
{
    Enter_Method("registerHook()");
    hooks.insert(std::pair<int, INetfilter::IHook *>(priority, hook));
}

void IPv4::unregisterHook(int priority, INetfilter::IHook *hook)
{
    Enter_Method("unregisterHook()");
    for (auto iter = hooks.begin(); iter != hooks.end(); iter++) {
        if ((iter->first == priority) && (iter->second == hook)) {
            hooks.erase(iter);
            return;
        }
    }
}

void IPv4::dropQueuedDatagram(const INetworkDatagram *datagram)
{
    Enter_Method("dropQueuedDatagram()");
    for (auto iter = queuedDatagramsForHooks.begin(); iter != queuedDatagramsForHooks.end(); iter++) {
        if (iter->datagram == datagram) {
            delete datagram;
            queuedDatagramsForHooks.erase(iter);
            return;
        }
    }
}

void IPv4::reinjectQueuedDatagram(const INetworkDatagram *datagram)
{
    Enter_Method("reinjectDatagram()");
    for (auto iter = queuedDatagramsForHooks.begin(); iter != queuedDatagramsForHooks.end(); iter++) {
        if (iter->datagram == datagram) {
            IPv4Datagram *datagram = iter->datagram;
            take(datagram);
            switch (iter->hookType) {
            case INetfilter::IHook::LOCALOUT:
                datagramLocalOut(datagram, iter->outIE, iter->nextHopAddr);
                break;

            case INetfilter::IHook::PREROUTING:
                preroutingFinish(datagram, iter->inIE, iter->outIE, iter->nextHopAddr);
                break;

            case INetfilter::IHook::POSTROUTING:
                fragmentAndSend(datagram, iter->outIE, iter->nextHopAddr);
                break;

            case INetfilter::IHook::LOCALIN:
                reassembleAndDeliverFinish(datagram);
                break;

            case INetfilter::IHook::FORWARD:
                routeUnicastPacketFinish(datagram, iter->inIE, iter->outIE, iter->nextHopAddr);
                break;

            default:
                throw cRuntimeError("Unknown hook ID: %d", (int)(iter->hookType));
                break;
            }
            queuedDatagramsForHooks.erase(iter);
            return;
        }
    }
}

INetfilter::IHook::Result IPv4::datagramPreRoutingHook(INetworkDatagram *datagram, const InterfaceEntry *inIE, const InterfaceEntry *& outIE, L3Address& nextHopAddr)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramPreRoutingHook(datagram, inIE, outIE, nextHopAddr);
        switch (r) {
        case INetfilter::IHook::ACCEPT:
            break;    // continue iteration

        case INetfilter::IHook::DROP:
            delete datagram;
            return r;

        case INetfilter::IHook::QUEUE:
            queuedDatagramsForHooks.push_back(QueuedDatagramForHook(dynamic_cast<IPv4Datagram *>(datagram), inIE, outIE, nextHopAddr.toIPv4(), INetfilter::IHook::PREROUTING));
            return r;

        case INetfilter::IHook::STOLEN:
            return r;

        default:
            throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result IPv4::datagramForwardHook(INetworkDatagram *datagram, const InterfaceEntry *inIE, const InterfaceEntry *& outIE, L3Address& nextHopAddr)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramForwardHook(datagram, inIE, outIE, nextHopAddr);
        switch (r) {
        case INetfilter::IHook::ACCEPT:
            break;    // continue iteration

        case INetfilter::IHook::DROP:
            delete datagram;
            return r;

        case INetfilter::IHook::QUEUE:
            queuedDatagramsForHooks.push_back(QueuedDatagramForHook(dynamic_cast<IPv4Datagram *>(datagram), inIE, outIE, nextHopAddr.toIPv4(), INetfilter::IHook::FORWARD));
            return r;

        case INetfilter::IHook::STOLEN:
            return r;

        default:
            throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result IPv4::datagramPostRoutingHook(INetworkDatagram *datagram, const InterfaceEntry *inIE, const InterfaceEntry *& outIE, L3Address& nextHopAddr)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramPostRoutingHook(datagram, inIE, outIE, nextHopAddr);
        switch (r) {
        case INetfilter::IHook::ACCEPT:
            break;    // continue iteration

        case INetfilter::IHook::DROP:
            delete datagram;
            return r;

        case INetfilter::IHook::QUEUE:
            queuedDatagramsForHooks.push_back(QueuedDatagramForHook(dynamic_cast<IPv4Datagram *>(datagram), inIE, outIE, nextHopAddr.toIPv4(), INetfilter::IHook::POSTROUTING));
            return r;

        case INetfilter::IHook::STOLEN:
            return r;

        default:
            throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

bool IPv4::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent();
    if (dynamic_cast<NodeStartOperation *>(operation)) {
        if ((NodeStartOperation::Stage)stage == NodeStartOperation::STAGE_NETWORK_LAYER)
            start();
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation)) {
        if ((NodeShutdownOperation::Stage)stage == NodeShutdownOperation::STAGE_NETWORK_LAYER)
            stop();
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation)) {
        if ((NodeCrashOperation::Stage)stage == NodeCrashOperation::STAGE_CRASH)
            stop();
    }
    return true;
}

void IPv4::start()
{
    ASSERT(queue.isEmpty());
    isUp = true;
}

void IPv4::stop()
{
    isUp = false;
    flush();
}

void IPv4::flush()
{
    delete cancelService();
    EV_DEBUG << "IPv4::flush(): packets in queue: " << queue.str() << endl;
    queue.clear();

    EV_DEBUG << "IPv4::flush(): pending packets:\n";
    for (auto & elem : pendingPackets) {
        EV_DEBUG << "IPv4::flush():    " << elem.first << ": " << elem.second.str() << endl;
        elem.second.clear();
    }
    pendingPackets.clear();

    EV_DEBUG << "IPv4::flush(): packets in hooks: " << queuedDatagramsForHooks.size() << endl;
    for (auto & elem : queuedDatagramsForHooks) {
        delete elem.datagram;
    }
    queuedDatagramsForHooks.clear();
}

bool IPv4::isNodeUp()
{
    NodeStatus *nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));
    return !nodeStatus || nodeStatus->getState() == NodeStatus::UP;
}

INetfilter::IHook::Result IPv4::datagramLocalInHook(INetworkDatagram *datagram, const InterfaceEntry *inIE)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramLocalInHook(datagram, inIE);
        switch (r) {
        case INetfilter::IHook::ACCEPT:
            EV_INFO <<"inside ipv4datagramlocal\n";
            break;    // continue iteration

        case INetfilter::IHook::DROP:
            delete datagram;
            return r;

        case INetfilter::IHook::QUEUE: {
            IPv4Datagram *dgram = check_and_cast<IPv4Datagram *>(datagram);
            if (dgram->getOwner() != this)
                throw cRuntimeError("Model error: netfilter hook changed the owner of queued datagram '%s'", dgram->getFullName());
            queuedDatagramsForHooks.push_back(QueuedDatagramForHook(dgram, inIE, nullptr, IPv4Address::UNSPECIFIED_ADDRESS, INetfilter::IHook::LOCALIN));
            return r;
        }

        case INetfilter::IHook::STOLEN:
            return r;

        default:
            throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

INetfilter::IHook::Result IPv4::datagramLocalOutHook(INetworkDatagram *datagram, const InterfaceEntry *& outIE, L3Address& nextHopAddr)
{
    for (auto & elem : hooks) {
        IHook::Result r = elem.second->datagramLocalOutHook(datagram, outIE, nextHopAddr);
        switch (r) {
        case INetfilter::IHook::ACCEPT:
            break;    // continue iteration

        case INetfilter::IHook::DROP:
            delete datagram;
            return r;

        case INetfilter::IHook::QUEUE:
            queuedDatagramsForHooks.push_back(QueuedDatagramForHook(dynamic_cast<IPv4Datagram *>(datagram), nullptr, outIE, nextHopAddr.toIPv4(), INetfilter::IHook::LOCALOUT));
            return r;

        case INetfilter::IHook::STOLEN:
            return r;

        default:
            throw cRuntimeError("Unknown Hook::Result value: %d", (int)r);
        }
    }
    return INetfilter::IHook::ACCEPT;
}

void IPv4::sendOnTransportOutGateByProtocolId(cPacket *packet, int protocolId)
{
    int gateindex = mapping.getOutputGateForProtocol(protocolId);
    cGate *outGate = gate("transportOut", gateindex);
    send(packet, outGate);
    emit(LayeredProtocolBase::packetSentToUpperSignal, packet);
}

void IPv4::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method_Silent();

    if (signalID == IARP::completedARPResolutionSignal) {
        arpResolutionCompleted(check_and_cast<IARP::Notification *>(obj));
    }
    if (signalID == IARP::failedARPResolutionSignal) {
        arpResolutionTimedOut(check_and_cast<IARP::Notification *>(obj));
    }
}


} // namespace inet
