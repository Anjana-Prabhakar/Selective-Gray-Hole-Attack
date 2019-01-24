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

#ifndef __INET_CSMAMAC_H
#define __INET_CSMAMAC_H



#include "inet/common/FSMA.h"
#include "inet/common/queue/IPassiveQueue.h"
#include "inet/common/queue/PacketQueue.h"
#include "inet/linklayer/base/MACProtocolBase.h"
#include "inet/physicallayer/contract/packetlevel/IRadio.h"
#include "inet/linklayer/csmaca/CsmaCaMacFrame_m.h"

namespace inet {

using namespace inet::physicallayer;
//@Anjana
INET_API long* getUpdateA();
INET_API long* getUpdateC();
INET_API long* getUpdate();

INET_API long* getUpdateSentA();
INET_API long* getUpdateSentC();

class INET_API CsmaCaMac : public MACProtocolBase
{
protected:
    /**
     * @name Configuration parameters
     */
    //@{
    MACAddress address;
    bool useAck = true;
    double bitrate = NaN;
    int headerLength = -1;
    int ackLength = -1;
    simtime_t ackTimeout = -1;//initially set to -1 changed to -10 by Anjana
    simtime_t slotTime = -1;
    simtime_t sifsTime = -1;//initially set to -1 changed to -10 by Anjana
    simtime_t difsTime = -1;
    int maxQueueSize = -1;
    int retryLimit = -1;
    int cwMin = -1;
    int cwMax = -1;
    int cwMulticast = -1;

    simtime_t updateTime = -1;//@Anjana

    static simsignal_t drpPkChannelSignal;
    double channelDropProbability=0;
    //@}

    /**
     * @name CsmaCaMac state variables
     * Various state information checked and modified according to the state machine.
     */
    //@{
    enum State {
        IDLE,
        DEFER,
        WAITDIFS,
        BACKOFF,
        TRANSMIT,
        WAITACK,
        RECEIVE,
        WAITSIFS,
        UPDATER,
        UPDATES,

    };

    IRadio *radio = nullptr;
    IRadio::TransmissionState transmissionState = IRadio::TRANSMISSION_STATE_UNDEFINED;

    cFSM fsm;

    /** Remaining backoff period in seconds */
    simtime_t backoffPeriod = -1;

    /** Number of frame retransmission attempts. */
    int retryCounter = -1;

    /** Messages received from upper layer and to be transmitted later */
    PacketQueue transmissionQueue;

    /** Passive queue module to request messages from */
    IPassiveQueue *queueModule = nullptr;
    //@}

    /** @name Timer messages */
    //@{
    /** End of the Short Inter-Frame Time period */
    cMessage *endSifs = nullptr;

    /** End of the Data Inter-Frame Time period */
    cMessage *endDifs = nullptr;

    /** End of the backoff period */
    cMessage *endBackoff = nullptr;

    /** End of the ack timeout */
    cMessage *endAckTimeout = nullptr;

    /** Timeout after the transmission of a Data frame */
    cMessage *endData = nullptr;

    /** Radio state change self message. Currently this is optimized away and sent directly */
    cMessage *mediumStateChange = nullptr;
    //@}
    //@Anjana
    /** End of the Update sending Time period */
    cMessage *endEvaluationTxr = nullptr;
    cMessage *endEvaluationRxr = nullptr;

    /** @name Statistics */
    //@{
    long numRetry;
    long numSentWithoutRetry;
    long numGivenUp;
    long numCollision;
    long numSent;
    long numReceived;
    long numSentBroadcast;
    long numReceivedBroadcast;
    //@}
    //extern int numFwdDownstream;
    //long numFwdDownstream;
    // long numFwdDownstreamC;
    /*long numSentWithoutRetryA;
    long numSentWithoutRetryC;
    long numSentA;
    long numSentC;*/
    int nFD;
    long origin=5;
    long orgId=5;

    int numSentData=0;
    int numBreak=0;
    //int numSentInfo[2]={0};
    long numSentInfo[2]={0};
    //long numSentC=0;
public:

    //long numFwdDownstreamInfo;
    /**
     * @name Construction functions
     */
    //@{
    virtual ~CsmaCaMac();
    //@}

protected:
    /**
     * @name Initialization functions
     */
    //@{
    /** @brief Initialization of the module and its variables */
    virtual void initialize(int stage) override;
    virtual void initializeQueueModule();
    virtual void finish() override;
    virtual InterfaceEntry *createInterfaceEntry() override;
    //@}

    /**
     * @name Message handing functions
     * @brief Functions called from other classes to notify about state changes and to handle messages.
     */
    //@{
    virtual void handleSelfMessage(cMessage *msg) override;
    virtual void handleUpperPacket(cPacket *msg) override;
    virtual void handleLowerPacket(cPacket *msg) override;
    virtual void handleWithFsm(cMessage *msg);

    virtual void receiveSignal(cComponent *source, simsignal_t signalID, long value, cObject *details) override;

    virtual CsmaCaMacDataFrame *encapsulate(cPacket *msg);
    virtual cPacket *decapsulate(CsmaCaMacDataFrame *frame);
    // virtual cPacket *decapsulate_ack(CsmaCaMacAckFrame *frame);
    //@}

    /**
     * @name Timer functions
     * @brief These functions have the side effect of starting the corresponding timers.
     */
    //@{
    virtual void scheduleSifsTimer(CsmaCaMacFrame *frame);

    virtual void scheduleDifsTimer();
    virtual void cancelDifsTimer();

    virtual void scheduleAckTimeout(CsmaCaMacDataFrame *frame);
    virtual void cancelAckTimer();

    virtual void invalidateBackoffPeriod();
    virtual bool isInvalidBackoffPeriod();
    virtual void generateBackoffPeriod();
    virtual void decreaseBackoffPeriod();
    virtual void scheduleBackoffTimer();
    virtual void cancelBackoffTimer();
    //@}
    //@Anjana
    virtual void scheduleUpdateSendTimer(CsmaCaMacFrame *frame);

    virtual void scheduleUpdateRecTimeout(CsmaCaMacDataFrame *frame);
    virtual void cancelUpdateRecTimer();

    /**
     * @name Frame transmission functions
     */
    //@{
    virtual void sendDataFrame(CsmaCaMacDataFrame *frameToSend);
    virtual void sendAckFrame();
    //@}
    //virtual void sendUpdateFrame();//@Anjana

    /**
     * @name Utility functions
     */
    //@{
    virtual void finishCurrentTransmission();
    virtual void giveUpCurrentTransmission();
    virtual void retryCurrentTransmission();
    virtual CsmaCaMacDataFrame *getCurrentTransmission();
    virtual void popTransmissionQueue();
    virtual void resetStateVariables();

    virtual bool isMediumFree();
    virtual bool isReceiving();
    virtual bool isAck(CsmaCaMacFrame *frame);
    virtual bool isBroadcast(CsmaCaMacFrame *msg);
    virtual bool isForUs(CsmaCaMacFrame *msg);
    //@}
};

} // namespace inet

#endif // ifndef __INET_CSMAMAC_H
