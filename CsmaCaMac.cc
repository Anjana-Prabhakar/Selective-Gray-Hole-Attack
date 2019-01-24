//
// Copyright (C) 2016 OpenSim Ltd.
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

#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/common/Ieee802Ctrl.h"
#include "inet/linklayer/common/UserPriority.h"
#include "inet/linklayer/csmaca/CsmaCaMac.h"

#include "inet/networklayer/ipv4/IPv4.h"

namespace inet {

Define_Module(CsmaCaMac);

static long numFwdDownstreamInfoA[6]={0};
static long numFwdDownstreamInfoC[6]={0};
static long numRecInfo[4]={0};

static long numSentA[6]={0};
static long numSentC[6]={0};
static long numSentWithoutRetryC[6]={0};
static long numSentWithoutRetryA[6]={0};
//long numFwdDownstreamInfo=0;

static int getUPBasedFramePriority(cObject *obj)
{
    auto frame = check_and_cast<CsmaCaMacDataFrame*>(obj);
    int up = frame->getPriority();
    return (up == UP_BK) ? -2 : (up == UP_BK2) ? -1 : up;  // because UP_BE==0, but background traffic should have lower priority than best effort
}

static int compareFramesByPriority(cObject *a, cObject *b)
{
    return getUPBasedFramePriority(b) - getUPBasedFramePriority(a);
}
//@Anjana
long* getUpdate()
{

    for(int i=0;i<=3;i++)
        EV<<"inside getUpdate. The value of numRecInfo is:"<<numRecInfo[i]<<endl;

    return numRecInfo;
}
long* getUpdateA()
{
    //long info=numFwdDownstreamInfo[nodeIndex];
    for(int i=0;i<=5;i++)
        EV<<"inside getUpdateA. The value of numFwdDownstreamInfoA is:"<<numFwdDownstreamInfoA[i]<<endl;

    return numFwdDownstreamInfoA;
}

long* getUpdateC()
{
    //long info=numFwdDownstreamInfo[nodeIndex];
    for(int i=0;i<=5;i++)
        EV<<"inside getUpdateC. The value of numFwdDownstreamInfoC is:"<<numFwdDownstreamInfoC[i]<<endl;

    return numFwdDownstreamInfoC;
}

long* getUpdateSentA()
{
    //long info=numFwdDownstreamInfo[nodeIndex];
    for(int i=0;i<=5;i++)
        EV<<"inside getUpdateSentA. The value of numSentA is:"<<numSentA[i]<<endl;

    return numSentA;
}
long* getUpdateSentC()
{
    //long info=numFwdDownstreamInfo[nodeIndex];
    for(int i=0;i<=5;i++)
        EV<<"inside getUpdateSentC. The value of numSentC is:"<<numSentC[i]<<endl;

    return numSentC;
}

simsignal_t CsmaCaMac::drpPkChannelSignal = SIMSIGNAL_NULL;
CsmaCaMac::~CsmaCaMac()
{
    cancelAndDelete(endSifs);
    cancelAndDelete(endDifs);
    cancelAndDelete(endBackoff);
    cancelAndDelete(endAckTimeout);
    cancelAndDelete(endData);
    cancelAndDelete(mediumStateChange);

    //@anjana
    /*cancelAndDelete(endEvaluationTxr);
    cancelAndDelete(endEvaluationRxr);*/
}

/****************************************************************
 * Initialization functions.
 */
void CsmaCaMac::initialize(int stage)
{
    MACProtocolBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        EV << "Initializing stage 0\n";


        maxQueueSize = par("maxQueueSize");
        useAck = par("useAck");
        bitrate = par("bitrate");
        headerLength = par("headerLength");
        ackLength = par("ackLength");
        ackTimeout = par("ackTimeout");
        slotTime = par("slotTime");
        sifsTime = par("sifsTime");
        difsTime = par("difsTime");
        cwMin = par("cwMin");
        cwMax = par("cwMax");
        cwMulticast = par("cwMulticast");
        retryLimit = par("retryLimit");

        const char *addressString = par("address");
        if (!strcmp(addressString, "auto")) {
            // assign automatic address
            address = MACAddress::generateAutoAddress();
            // change module parameter from "auto" to concrete address
            par("address").setStringValue(address.str().c_str());
        }
        else
            address.setAddress(addressString);
        registerInterface();

        // subscribe for the information of the carrier sense
        cModule *radioModule = getModuleFromPar<cModule>(par("radioModule"), this);
        radioModule->subscribe(IRadio::receptionStateChangedSignal, this);
        radioModule->subscribe(IRadio::transmissionStateChangedSignal, this);
        radio = check_and_cast<IRadio *>(radioModule);

        // initialize self messages
        endSifs = new cMessage("SIFS");
        endDifs = new cMessage("DIFS");
        endBackoff = new cMessage("Backoff");
        endAckTimeout = new cMessage("AckTimeout");
        endData = new cMessage("Data");
        mediumStateChange = new cMessage("MediumStateChange");

        // set up internal queue
        transmissionQueue.setMaxPacketLength(maxQueueSize);
        transmissionQueue.setName("transmissionQueue");
        if (par("prioritizeByUP"))
            transmissionQueue.setup(&compareFramesByPriority);

        // obtain pointer to external queue
        initializeQueueModule();

        // state variables
        fsm.setName("CsmaCaMac State Machine");
        backoffPeriod = -1;
        retryCounter = 0;

        // statistics
        numRetry = 0;
        numSentWithoutRetry = 0;
        numGivenUp = 0;
        numCollision = 0;
        numSent = 0;
        numReceived = 0;
        numSentBroadcast = 0;
        numReceivedBroadcast = 0;

        //int numFwdDownstream=0;
        //numFwdDownstreamA=0;
        // numFwdDownstreamC=0;
        //numFwdDownstreamInfo=0;


        // initialize watches
        WATCH(fsm);
        WATCH(backoffPeriod);
        WATCH(retryCounter);
        WATCH(numRetry);
        WATCH(numSentWithoutRetry);
        WATCH(numGivenUp);
        WATCH(numCollision);
        WATCH(numSent);
        WATCH(numReceived);
        WATCH(numSentBroadcast);
        WATCH(numReceivedBroadcast);
    }
    else if (stage == INITSTAGE_LINK_LAYER)
        radio->setRadioMode(IRadio::RADIO_MODE_RECEIVER);
    drpPkChannelSignal = registerSignal("drpPkChannel");
}

void CsmaCaMac::initializeQueueModule()
{
    // use of external queue module is optional -- find it if there's one specified
    if (par("queueModule").stringValue()[0]) {
        cModule *module = getParentModule()->getSubmodule(par("queueModule").stringValue());
        queueModule = check_and_cast<IPassiveQueue *>(module);

        EV << "Requesting first two frames from queue module\n";
        queueModule->requestPacket();
        // needed for backoff: mandatory if next message is already present
        queueModule->requestPacket();
    }
}

void CsmaCaMac::finish()
{
    recordScalar("numRetry", numRetry);
    recordScalar("numSentWithoutRetry", numSentWithoutRetry);
    recordScalar("numGivenUp", numGivenUp);
    recordScalar("numCollision", numCollision);
    recordScalar("numSent", numSent);
    recordScalar("numReceived", numReceived);
    recordScalar("numSentBroadcast", numSentBroadcast);
    recordScalar("numReceivedBroadcast", numReceivedBroadcast);
    recordScalar("numReceivedBroadcast", numReceivedBroadcast);

    //recordScalar("numFwdDownstream", numFwdDownstream);
    //recordScalar("numFwdDownstreamC", numFwdDownstreamC);
}

InterfaceEntry *CsmaCaMac::createInterfaceEntry()
{
    InterfaceEntry *e = new InterfaceEntry(this);

    // data rate
    e->setDatarate(bitrate);

    // generate a link-layer address to be used as interface token for IPv6
    e->setMACAddress(address);
    e->setInterfaceToken(address.formInterfaceIdentifier());

    // capabilities
    e->setMtu(par("mtu"));
    e->setMulticast(true);
    e->setBroadcast(true);
    e->setPointToPoint(false);

    return e;
}

/****************************************************************
 * Message handling functions.
 */
void CsmaCaMac::handleSelfMessage(cMessage *msg)
{
    EV << "received self message: " << msg << endl;
    handleWithFsm(msg);
}

void CsmaCaMac::handleUpperPacket(cPacket *msg)
{
    if (maxQueueSize != -1 && (int)transmissionQueue.getLength() == maxQueueSize) {
        EV << "message " << msg << " received from higher layer but MAC queue is full, dropping message\n";
        emit(LayeredProtocolBase::packetFromUpperDroppedSignal, msg);
        delete msg;
        return;
    }

    CsmaCaMacDataFrame *frame = encapsulate(msg);
    if(frame->hasPar("origin"))
        EV<<"Origin appended"<<frame->par("origin").longValue()<<endl;
    EV << "frame " << frame << " received from higher layer, receiver = " << frame->getReceiverAddress() << endl;
    ASSERT(!frame->getReceiverAddress().isUnspecified());
    transmissionQueue.insert(frame);
    if (fsm.getState() != IDLE)
        EV << "deferring upper message transmission in " << fsm.getStateName() << " state\n";
    else
        handleWithFsm(frame);
}

void CsmaCaMac::handleLowerPacket(cPacket *msg)
{
    EV << "received message from lower layer: " << msg << endl;

    CsmaCaMacFrame *frame = check_and_cast<CsmaCaMacFrame *>(msg);
    EV << "Self address: " << address
            << ", receiver address: " << frame->getReceiverAddress()
            << ", received frame is for us: " << isForUs(frame) << endl;

    handleWithFsm(msg);
}

void CsmaCaMac::handleWithFsm(cMessage *msg)
{
    CsmaCaMacFrame *frame = dynamic_cast<CsmaCaMacFrame*>(msg);
    EV_DEBUG<<"Frame is"<<msg->getName()<<endl;

    FSMA_Switch(fsm)
    {
        FSMA_State(IDLE)
                                                        {
            FSMA_Event_Transition(Defer-Transmit,
                    isUpperMessage(msg) && !isMediumFree(),
                    DEFER,
            );
            FSMA_Event_Transition(Start-Backoff,
                    isUpperMessage(msg) && isMediumFree() && !useAck,
                    BACKOFF,
            );
            FSMA_Event_Transition(Start-Difs,
                    isUpperMessage(msg) && isMediumFree() && useAck,
                    WAITDIFS,
            );
            FSMA_Event_Transition(Start-Receive,
                    msg == mediumStateChange && isReceiving(),
                    RECEIVE,
            );
                                                        }
        FSMA_State(DEFER)
        {
            FSMA_Event_Transition(Start-Backoff,
                    msg == mediumStateChange && isMediumFree() && !useAck,
                    BACKOFF,
            );
            FSMA_Event_Transition(Start-Difs,
                    msg == mediumStateChange && isMediumFree() && useAck,
                    WAITDIFS,
            );
            FSMA_Event_Transition(Start-Receive,
                    msg == mediumStateChange && isReceiving(),
                    RECEIVE,
            );
        }
        FSMA_State(WAITDIFS)
        {
            FSMA_Enter(scheduleDifsTimer());
            FSMA_Event_Transition(Start-Backoff,
                    msg == endDifs,
                    BACKOFF,
            );
            FSMA_Event_Transition(Start-Receive,
                    msg == mediumStateChange && isReceiving(),
                    RECEIVE,
                    cancelDifsTimer();
            );
            FSMA_Event_Transition(Defer-Difs,
                    msg == mediumStateChange && !isMediumFree(),
                    DEFER,
                    cancelDifsTimer();
            );
        }
        FSMA_State(BACKOFF)
        {
            FSMA_Enter(scheduleBackoffTimer());
            FSMA_Event_Transition(Start-Transmit,
                    msg == endBackoff,
                    TRANSMIT,
                    invalidateBackoffPeriod();
            );
            FSMA_Event_Transition(Start-Receive,
                    msg == mediumStateChange && isReceiving(),
                    RECEIVE,
                    cancelBackoffTimer();
            decreaseBackoffPeriod();
            );
            FSMA_Event_Transition(Defer-Backoff,
                    msg == mediumStateChange && !isMediumFree(),
                    DEFER,
                    cancelBackoffTimer();
            decreaseBackoffPeriod();
            );
        }
        FSMA_State(TRANSMIT)
        {
            //if (getCurrentTransmission()->getTransmitterAddress() != nullptr)
            //{
            /*MACAddress& sender=getCurrentTransmission()->getTransmitterAddress();
    EV_INFO<<"MACAddress of sender:"<<sender<<endl;*/
            //}
            FSMA_Enter(sendDataFrame(getCurrentTransmission()));
            FSMA_Event_Transition(Transmit-Broadcast,
                    msg == endData && isBroadcast(getCurrentTransmission()),
                    IDLE,
                    finishCurrentTransmission();
            numSentBroadcast++;
            );
            FSMA_Event_Transition(Transmit-Unicast-No-Ack,
                    msg == endData && !useAck && !isBroadcast(getCurrentTransmission()),
                    IDLE,
                    //@Anjana
                    /* if(!endEvaluationTxr->isScheduled())
                                      scheduleUpdateRecTimeout(getCurrentTransmission());*/
                    finishCurrentTransmission();
            numSent++;

            );
            FSMA_Event_Transition(Transmit-Unicast-Use-Ack,
                    msg == endData && useAck && !isBroadcast(getCurrentTransmission()),
                    WAITACK,

                    //if (getCurrentTransmission()->hasPar("origin"))
                    //{
                    EV<<"Frame name-2 is"<<getCurrentTransmission()->getName()<<endl;
            EV<<"inside txn"<<endl;
            MACAddress& currentNode=getCurrentTransmission()->getTransmitterAddress();
            orgId=getCurrentTransmission()->par("origin").longValue();
            if(orgId<5)
            {
                if(currentNode==MACAddress("0A-AA-00-00-00-01"))
                {
                    if(orgId==0)
                    {
                        if (retryCounter == 0) numSentWithoutRetryA[0]++;
                        numSentA[0]++;
                    }
                    else if (orgId==1)
                    {
                        if (retryCounter == 0) numSentWithoutRetryC[0]++;
                        numSentC[0]++;
                    }
                }
                else if(currentNode==MACAddress("0A-AA-00-00-00-03"))
                {
                    if(orgId==0)
                    {
                        if (retryCounter == 0) numSentWithoutRetryA[1]++;
                        numSentA[1]++;
                    }
                    else if (orgId==1)
                    {
                        if (retryCounter == 0) numSentWithoutRetryC[1]++;
                        numSentC[1]++;
                    }
                }
                else if(currentNode==MACAddress("0A-AA-00-00-00-04"))
                {
                    if(orgId==0)
                    {
                        if (retryCounter == 0) numSentWithoutRetryA[2]++;
                        numSentA[2]++;
                    }
                    else if (orgId==1)
                    {
                        if (retryCounter == 0) numSentWithoutRetryC[2]++;
                        numSentC[2]++;
                    }
                }
                else if(currentNode==MACAddress("0A-AA-00-00-00-05"))
                {
                    if(orgId==0)
                    {
                        if (retryCounter == 0) numSentWithoutRetryA[3]++;
                        numSentA[3]++;
                    }
                    else if (orgId==1)
                    {
                        if (retryCounter == 0) numSentWithoutRetryC[3]++;
                        numSentC[3]++;
                    }
                }
                else if(currentNode==MACAddress("0A-AA-00-00-00-06"))
                {
                    if(orgId==0)
                    {
                        if (retryCounter == 0) numSentWithoutRetryA[4]++;
                        numSentA[4]++;
                    }
                    else if (orgId==1)
                    {
                        if (retryCounter == 0) numSentWithoutRetryC[4]++;
                        numSentC[4]++;
                    }
                }
                else if(currentNode==MACAddress("0A-AA-00-00-00-07"))
                {
                    if(orgId==0)
                    {
                        if (retryCounter == 0) numSentWithoutRetryA[5]++;
                        numSentA[5]++;
                    }
                    else if (orgId==1)
                    {
                        if (retryCounter == 0) numSentWithoutRetryC[5]++;
                        numSentC[5]++;
                    }
                }
                // }
            }
            if (retryCounter == 0) numSentWithoutRetry++;
            numSent++;


            );

        }

        FSMA_State(WAITACK)
        {
            FSMA_Enter(scheduleAckTimeout(getCurrentTransmission()));
            FSMA_Event_Transition(Receive-Ack,
                    isLowerMessage(msg) && isForUs(frame) && isAck(frame),
                    IDLE,
                    // if (retryCounter == 0) numSentWithoutRetry++;
                    //numSent++;
                    //@Anjana

                    if(frame->hasPar("nFD"))
                    {
                        EV_INFO<<"inside waitack: retrieving info\n";


                        int index= frame->findPar("nFD");
                        cArray& c=frame->getParList();
                        EV_INFO<<"parlist"<<c[0]<<endl;

                        //cArray& parlist = getParList();
                        cObject *p = c.get(index);
                        void *ptrinfo;
                        if (!p)
                            EV_WARN<<"par(int): Has no parameter #%d" <<index<<endl;
                        else
                            ptrinfo=frame->par(index).pointerValue();
                        int a[2]={0};
                        int *b=(int*)(ptrinfo);
                        a[0]=*(b+0);
                        a[1]=*(b+1);
                        MACAddress dest=frame->getReceiverAddress();
                        EV_INFO<<"MACAddress:"<<dest.str()<<endl;
                        if(dest==MACAddress("0A-AA-00-00-00-01"))
                        {
                            numFwdDownstreamInfoA[0]=a[0];


                            //long chk1=ptrinfo;
                            //long chk2=*ptrinfo;
                            //long chk3=&(ptrinfo);
                            //long chk4=&(ptrinfo+8);
                            EV_INFO<<"numFwdDownstreamInfo of A:"<<numFwdDownstreamInfoA[0]<<endl;

                        }

                        else if(dest==MACAddress("0A-AA-00-00-00-03"))
                        {
                            numFwdDownstreamInfoC[1]=a[1];
                            EV_INFO<<"numFwdDownstreamInfo of C:"<<numFwdDownstreamInfoC[1]<<endl;
                        }
                        else if(dest==MACAddress("0A-AA-00-00-00-04"))
                        {
                            //for numreceived info
                            numRecInfo[0]=numReceived;
                            numFwdDownstreamInfoA[2]=a[0];
                            numFwdDownstreamInfoC[2]=a[1];
                            EV_INFO<<"numFwdDownstreamInfo of R1:"<<numFwdDownstreamInfoA[2]<<"and"<<numFwdDownstreamInfoC[2]<<endl;
                        }
                        else if(dest==MACAddress("0A-AA-00-00-00-05"))
                        {
                            //for numreceived info
                            numRecInfo[1]=numReceived;
                            numFwdDownstreamInfoA[3]=a[0];
                            numFwdDownstreamInfoC[3]=a[1];
                            EV_INFO<<"numFwdDownstreamInfo of R2:"<<numFwdDownstreamInfoA[3]<<"and"<<numFwdDownstreamInfoC[3]<<endl;
                        }
                        else if(dest==MACAddress("0A-AA-00-00-00-06"))
                        {
                            //for numreceived info
                            numRecInfo[2]=numReceived;
                            numFwdDownstreamInfoA[4]=a[0];
                            numFwdDownstreamInfoC[4]=a[1];
                            EV_INFO<<"numFwdDownstreamInfo of R3:"<<numFwdDownstreamInfoA[4]<<"and"<<numFwdDownstreamInfoC[4]<<endl;
                        }
                        else if(dest==MACAddress("0A-AA-00-00-00-07"))
                        {
                            //for numreceived info
                            numRecInfo[3]=numReceived;
                            numFwdDownstreamInfoA[5]=a[0];
                            numFwdDownstreamInfoC[5]=a[1];
                            EV_INFO<<"numFwdDownstreamInfo of R4:"<<numFwdDownstreamInfoA[5]<<"and"<<numFwdDownstreamInfoC[5]<<endl;
                        }

                        else
                            EV_WARN<<"wrong MAC address"<<dest<<endl;
                        // end of value retrieval from netwrk layer*/

                    }


            cancelAckTimer();
            finishCurrentTransmission();
            delete frame;
            );
            FSMA_Event_Transition(Give-Up-Transmission,
                    msg == endAckTimeout && retryCounter == retryLimit,
                    IDLE,
                    //numBreak++;
                    giveUpCurrentTransmission();

            );
            FSMA_Event_Transition(Retry-Transmission,
                    msg == endAckTimeout,
                    IDLE,
                    retryCurrentTransmission();
            //giveUpCurrentTransmission();
            );

        }
        FSMA_State(RECEIVE)
        {
            FSMA_Event_Transition(Receive-Bit-Error,
                    isLowerMessage(msg) && frame->hasBitError(),
                    IDLE,
                    // TODO: reason? emit(LayeredProtocolBase::packetFromLowerDroppedSignal, frame);
                    delete frame;
            numCollision++;
            resetStateVariables();
            );
            FSMA_Event_Transition(Receive-Unexpected-Ack,
                    isLowerMessage(msg) && isAck(frame),
                    IDLE,
                    delete frame;
            resetStateVariables();
            );
            FSMA_Event_Transition(Receive-Broadcast,
                    isLowerMessage(msg) && isBroadcast(frame),
                    IDLE,
                    sendUp(decapsulate(check_and_cast<CsmaCaMacDataFrame *>(frame)));
            numReceivedBroadcast++;
            resetStateVariables();
            );
            FSMA_Event_Transition(Receive-Unicast-No-Ack,
                    isLowerMessage(msg) && isForUs(frame) && !useAck,
                    IDLE,
                    sendUp(decapsulate(check_and_cast<CsmaCaMacDataFrame *>(frame)));
            numReceived++;
            //@Anjana
            /*if (!endEvaluationRxr->isScheduled())
                    scheduleUpdateSendTimer(frame);*/
            resetStateVariables();
            );
            FSMA_Event_Transition(Receive-Unicast-Use-Ack,
                    isLowerMessage(msg) && isForUs(frame) && useAck,
                    WAITSIFS,
                    if((1.0 - channelDropProbability) <= dblrand())
                    {

                        emit(drpPkChannelSignal, frame);

                        EV << "Packet Dropped-channel\n";
                        delete frame;
                        delete msg;  // keeps OMNeT++ happy
                        return;

                    }
                    else
                    {

                        sendUp(decapsulate(check_and_cast<CsmaCaMacDataFrame *>(frame->dup())));
                        numReceived++;
                    }
            );
            FSMA_Event_Transition(Receive-Unicast-Not-For-Us,
                    isLowerMessage(msg) && !isForUs(frame),
                    IDLE,
                    delete frame;
            resetStateVariables();
            );
        }
        FSMA_State(WAITSIFS)
        {
            FSMA_Enter(scheduleSifsTimer(frame));
            FSMA_Event_Transition(Transmit-Ack,
                    msg == endSifs,
                    IDLE,
                    sendAckFrame();
            resetStateVariables();
            );
        }
    }
    if (fsm.getState() == IDLE) {
        if (isReceiving())
            handleWithFsm(mediumStateChange);
        else if (!transmissionQueue.isEmpty())
            handleWithFsm(transmissionQueue.front());
    }
}



void CsmaCaMac::receiveSignal(cComponent *source, simsignal_t signalID, long value, cObject *details)
{
    Enter_Method_Silent();
    if (signalID == IRadio::receptionStateChangedSignal)
        handleWithFsm(mediumStateChange);
    else if (signalID == IRadio::transmissionStateChangedSignal) {
        IRadio::TransmissionState newRadioTransmissionState = (IRadio::TransmissionState)value;
        if (transmissionState == IRadio::TRANSMISSION_STATE_TRANSMITTING && newRadioTransmissionState == IRadio::TRANSMISSION_STATE_IDLE) {
            handleWithFsm(endData);
            radio->setRadioMode(IRadio::RADIO_MODE_RECEIVER);
        }
        transmissionState = newRadioTransmissionState;
    }
}

CsmaCaMacDataFrame *CsmaCaMac::encapsulate(cPacket *msg)
{

    CsmaCaMacDataFrame *frame = new CsmaCaMacDataFrame(msg->getName());
    frame->setByteLength(headerLength);
    // TODO: kludge to make isUpperMessage work
    frame->setArrival(msg->getArrivalModuleId(), msg->getArrivalGateId());


    EV_INFO<<"Inside Encapsulate.source addr is:"<<check_and_cast<IPv4Datagram *>(msg)->getSourceAddress()<<endl;
    Ieee802Ctrl *ctrl = check_and_cast<Ieee802Ctrl *>(msg->removeControlInfo());
    frame->setTransmitterAddress(address);
    frame->setReceiverAddress(ctrl->getDest());
    //ctrl->getSrc();
    int up = ctrl->getUserPriority();
    frame->setPriority(up == -1 ? UP_BE : up);  // -1 is unset
    //@Anjana
    L3Address src=check_and_cast<IPv4Datagram *>(msg)->getSourceAddress();
    long origin=5;
    if (src == IPv4Address("10.0.0.3"))
        origin=1;
    else if (src ==IPv4Address("10.0.0.1"))
        origin=0;

    //end addition




    delete ctrl;

    frame->encapsulate(msg);
    //@Anjana
    frame->addPar("origin");
    frame->par("origin").setLongValue(origin);
    //end addn
    return frame;
}

cPacket *CsmaCaMac::decapsulate(CsmaCaMacDataFrame *frame)
{
    cPacket *payload = frame->decapsulate();

    Ieee802Ctrl *ctrl = new Ieee802Ctrl();
    ctrl->setSrc(frame->getTransmitterAddress());
    ctrl->setDest(frame->getReceiverAddress());
    ctrl->setUserPriority(frame->getPriority());
    payload->setControlInfo(ctrl);
    delete frame;
    return payload;
}

//@Anjana
/*cPacket *CsmaCaMac::decapsulate_ack(CsmaCaMacAckFrame *frame)
{
    cPacket *payload = frame->decapsulate();

    Ieee802Ctrl *ctrl = new Ieee802Ctrl();
    ctrl->setSrc(frame->getTransmitterAddress());
    ctrl->setDest(frame->getReceiverAddress());

frame->
    // ctrl->setUserPriority(frame->getPriority());
    //payload->setControlInfo(ctrl);


    delete frame;
    return payload;
}*/

/****************************************************************
 * Timer functions.
 */
void CsmaCaMac::scheduleSifsTimer(CsmaCaMacFrame *frame)
{
    EV << "scheduling SIFS timer\n";
    endSifs->setContextPointer(frame);
    scheduleAt(simTime() + sifsTime, endSifs);
}

void CsmaCaMac::scheduleDifsTimer()
{
    EV << "scheduling DIFS timer\n";
    scheduleAt(simTime() + difsTime, endDifs);
}

void CsmaCaMac::cancelDifsTimer()
{
    EV << "canceling DIFS timer\n";
    cancelEvent(endDifs);
}

void CsmaCaMac::scheduleAckTimeout(CsmaCaMacDataFrame *frameToSend)
{
    EV << "scheduling ACK timeout\n";
    scheduleAt(simTime() + ackTimeout, endAckTimeout);
}

void CsmaCaMac::cancelAckTimer()
{
    EV << "canceling ACK timer\n";
    cancelEvent(endAckTimeout);
}

//@Anjana
void CsmaCaMac::scheduleUpdateSendTimer(CsmaCaMacFrame *frame)
{
    EV << "scheduling Update sending timer\n";
    endEvaluationRxr->setContextPointer(frame);
    scheduleAt(simTime() + updateTime, endEvaluationRxr);
}
void CsmaCaMac::scheduleUpdateRecTimeout(CsmaCaMacDataFrame *frameToSend)
{
    EV << "scheduling update receive timeout\n";
    scheduleAt(simTime() + updateTime, endEvaluationTxr);
}
void CsmaCaMac::cancelUpdateRecTimer()
{
    EV << "canceling Update timer\n";
    cancelEvent(endEvaluationTxr);

}

void CsmaCaMac::invalidateBackoffPeriod()
{
    backoffPeriod = -1;
}

bool CsmaCaMac::isInvalidBackoffPeriod()
{
    return backoffPeriod == -1;
}

void CsmaCaMac::generateBackoffPeriod()
{
    ASSERT(0 <= retryCounter && retryCounter <= retryLimit);
    EV << "generating backoff slot number for retry: " << retryCounter << endl;
    int cw;
    if (getCurrentTransmission()->getReceiverAddress().isMulticast())
        cw = cwMulticast;
    else
        cw = std::min(cwMax, (cwMin + 1) * (1 << retryCounter) - 1);
    int slots = intrand(cw + 1);
    EV << "generated backoff slot number: " << slots << " , cw: " << cw << endl;
    backoffPeriod = slots * slotTime;
    ASSERT(backoffPeriod >= 0);
    EV << "backoff period set to " << backoffPeriod << endl;
}

void CsmaCaMac::decreaseBackoffPeriod()
{
    simtime_t elapsedBackoffTime = simTime() - endBackoff->getSendingTime();
    backoffPeriod -= ((int)(elapsedBackoffTime / slotTime)) * slotTime;
    ASSERT(backoffPeriod >= 0);
    EV << "backoff period decreased to " << backoffPeriod << endl;
}

void CsmaCaMac::scheduleBackoffTimer()
{
    EV << "scheduling backoff timer\n";
    if (isInvalidBackoffPeriod())
        generateBackoffPeriod();
    scheduleAt(simTime() + backoffPeriod, endBackoff);
}

void CsmaCaMac::cancelBackoffTimer()
{
    EV << "canceling backoff timer\n";
    cancelEvent(endBackoff);
}


/****************************************************************
 * Frame sender functions.
 */
void CsmaCaMac::sendDataFrame(CsmaCaMacDataFrame *frameToSend)
{
    EV << "sending Data frame " << frameToSend->getName() << endl;
    radio->setRadioMode(IRadio::RADIO_MODE_TRANSMITTER);
    sendDown(frameToSend->dup());
}

void CsmaCaMac::sendAckFrame()
{
    EV << "sending Ack frame\n";
    auto frameToAck = static_cast<CsmaCaMacDataFrame *>(endSifs->getContextPointer());
    endSifs->setContextPointer(nullptr);


    auto ackFrame = new CsmaCaMacAckFrame("CsmaAck");
    ackFrame->setReceiverAddress(frameToAck->getTransmitterAddress());
    ackFrame->setByteLength(ackLength);
    int nodeIndex;
    //@Anjana
    MACAddress currentNode=frameToAck->getReceiverAddress();
    EV_INFO<<"MACAddress current node:"<<currentNode.str()<<endl;
    if(currentNode==MACAddress("0A-AA-00-00-00-01"))
    {
        nodeIndex=0;
    }
    else if (currentNode==MACAddress("0A-AA-00-00-00-03"))
    {
        nodeIndex=1;
    }
    else if(currentNode==MACAddress("0A-AA-00-00-00-04"))
    {
        nodeIndex=2;
    }
    else if (currentNode==MACAddress("0A-AA-00-00-00-05"))
    {
        nodeIndex=3;
    }
    else if (currentNode==MACAddress("0A-AA-00-00-00-06"))
    {
        nodeIndex=4;
    }
    else if (currentNode==MACAddress("0A-AA-00-00-00-07"))
    {
        nodeIndex=5;
    }
    else
    {
        EV_INFO<<"wrong mac id"<<currentNode;
        nodeIndex=6;
    }
    if(nodeIndex<=5)
    {
        /*long *ptrA=inet::getUpdateAfromIP();
        numSentInfo[0]=ptrA[nodeIndex];
        long *ptrC=inet::getUpdateCfromIP();
        numSentInfo[1]=ptrC[nodeIndex];*/

        numSentInfo[0]=numSentA[nodeIndex];
        numSentInfo[1]=numSentC[nodeIndex];


        void* numSentInfoPtr=numSentInfo;
        /*ackFrame->addPar("numFwdDownstreamC");
               ackFrame->par("numFwdDownstreamC").setLongValue(numSentC);*/
        // int nFD;

        ackFrame->addPar("nFD");
        int index=ackFrame->findPar("nFD");
        ackFrame->par(index).setPointerValue(numSentInfoPtr);
        EV_INFO<<"numsentA"<<numSentInfo[0]<<endl;
        EV_INFO<<"numsentC"<<numSentInfo[1]<<endl;


        // EV_INFO<<"ackframe.numFwdDownstreamC"<<ackFrame->par(numFwdDownstreamC).longValue()<<endl;
        // EV_INFO<<"ackframe.numFwdDownstreamA"<<ackFrame->par(numFwdDownstreamA).longValue()<<endl;
        //end adds
    }
    radio->setRadioMode(IRadio::RADIO_MODE_TRANSMITTER);
    sendDown(ackFrame);
    delete frameToAck;
}
//@Anjana
/*void CsmaCaMac::sendUpdateFrame()
{
    EV << "sending update frame\n";
    auto frameToUpdate = static_cast<CsmaCaMacDataFrame *>(endEvaluationRxr->getContextPointer());
    endEvaluationRxr->setContextPointer(nullptr);

     auto updateFrame = new CsmaCaMacAckFrame("updateFrame");
     updateFrame->setReceiverAddress(frameToUpdate->getTransmitterAddress());
     updateFrame->setByteLength(ackLength);

    //@Anjana
     updateFrame->addPar("numSentDownstream");
     updateFrame->par("numSentDownstream").setLongValue(numSent);
    //end adds
    radio->setRadioMode(IRadio::RADIO_MODE_TRANSMITTER);
    sendDown(updateFrame);
    delete frameToUpdate;
}*/

/****************************************************************
 * Helper functions.
 */
void CsmaCaMac::finishCurrentTransmission()
{
    popTransmissionQueue();
    resetStateVariables();
}

void CsmaCaMac::giveUpCurrentTransmission()
{
    /*if(numBreak>1)
    {*/
    // emit(NF_LINK_BREAK, getCurrentTransmission());
    /*  numBreak=0;
    }*/
    popTransmissionQueue();
    resetStateVariables();
    numGivenUp++;
}

void CsmaCaMac::retryCurrentTransmission()
{
    ASSERT(retryCounter < retryLimit);
    retryCounter++;
    numRetry++;
    generateBackoffPeriod();
}

CsmaCaMacDataFrame *CsmaCaMac::getCurrentTransmission()
{
    return static_cast<CsmaCaMacDataFrame*>(transmissionQueue.front());
}

void CsmaCaMac::popTransmissionQueue()
{
    EV << "dropping frame from transmission queue\n";
    delete transmissionQueue.pop();
    if (queueModule) {
        // tell queue module that we've become idle
        EV << "requesting another frame from queue module\n";
        queueModule->requestPacket();
    }
}

void CsmaCaMac::resetStateVariables()
{
    backoffPeriod = -1;
    retryCounter = 0;
}

bool CsmaCaMac::isMediumFree()
{
    return radio->getReceptionState() == IRadio::RECEPTION_STATE_IDLE;
}

bool CsmaCaMac::isReceiving()
{
    return radio->getReceptionState() == IRadio::RECEPTION_STATE_RECEIVING;
}

bool CsmaCaMac::isAck(CsmaCaMacFrame *frame)
{
    return dynamic_cast<CsmaCaMacAckFrame *>(frame);
}

bool CsmaCaMac::isBroadcast(CsmaCaMacFrame *frame)
{
    return frame->getReceiverAddress().isBroadcast();
}

bool CsmaCaMac::isForUs(CsmaCaMacFrame *frame)
{
    return frame->getReceiverAddress() == address;
}



} // namespace inet
