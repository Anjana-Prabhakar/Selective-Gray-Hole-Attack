//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package inet.tutorials.wireless;



import inet.node.inet.INetworkNode;
import inet.common.lifecycle.LifecycleController;
//import inet.status.NodeStatus;

network WirelessD extends WirelessAD
{
    parameters:
        @figure[dropPkText](type=indicatorText; pos=100,20; anchor=w; font=,10; textFormat="packets dropped: %g"; initialValue=0);
        @statistic[dropPkmal](source=hostR2_drpPkMalicious; record=figure(count); targetFigure=dropPkText);
        @signal[hostR2_drpPkMalicious];
        @delegatesignal[dropPkmal](source=hostR2.networkLayer.ip.drpPkMalicious; target=hostR2_drpPkMalicious);

        @figure[malStatText](type=indicatorText; pos=100,40; anchor=w; font=,10; textFormat="mal activity status: %g"; initialValue=0);
        @statistic[malStat](source=host_malStatus; record=figure(count),vector; targetFigure=malStatText);
        @signal[host_malStatus];


        @figure[detStatText](type=indicatorText; pos=100,60; anchor=w; font=,10; textFormat="mal activity detection status: %g"; initialValue=0);
        @statistic[detStat](source=host_detStatus; record=figure(count),vector; targetFigure=detStatText);
        @signal[host_detStatus];

    submodules:
        hostR1: <hostType> like INetworkNode {
            @display("p=250.992,303.40802");
        }
        hostR2: <hostType> like INetworkNode {
            @display("p=349.776,253.00801");
        }
        hostR3: <hostType> like INetworkNode {
            @display("p=441.504,303.40802");
        }

        hostR4: <hostType> like INetworkNode {
            @display("p=131.04001,303.40802");
        }
        lifecycleController: LifecycleController {
            parameters:
                @display("p=50,200");
        }
}

