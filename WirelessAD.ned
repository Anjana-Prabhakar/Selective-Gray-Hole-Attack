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

import inet.common.figures.DelegateSignalConfigurator;
import inet.networklayer.configurator.ipv4.IPv4NetworkConfigurator;
import inet.node.inet.INetworkNode;
import inet.physicallayer.contract.packetlevel.IRadioMedium;
import inet.visualizer.contract.IIntegratedVisualizer;


network WirelessAD
{
    parameters:
        string hostType = default("WirelessHost");
        string mediumType = default("IdealRadioMedium");

        @display("bgb=650,500;bgg=100,1,grey95");
        @figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[rcvdPkText](type=indicatorText; pos=420,20; anchor=w; font=,20; textFormat="packets received: %g"; initialValue=0);
        @statistic[rcvdPk](source=hostB_rcvdPk; record=figure(count); targetFigure=rcvdPkText);
        @signal[hostB_rcvdPk];
        @delegatesignal[rcvdPk](source=hostB.udpApp[0].rcvdPk; target=hostB_rcvdPk);

        @figure[sentPkText](type=indicatorText; pos=220,20; anchor=w; font=,20; textFormat="packets sent: %g"; initialValue=0);
        @statistic[sentPk](source=hostC_sentPk; record=figure(count); targetFigure=sentPkText);
        @signal[hostC_sentPk];
        @delegatesignal[sentPk](source=hostC.udpApp[0].sentPk; target=hostC_sentPk);

        @figure[sentPkText2](type=indicatorText; pos=220,40; anchor=w; font=,20; textFormat="packets sent: %g"; initialValue=0);
        @statistic[sentPk2](source=hostA_sentPk; record=figure(count); targetFigure=sentPkText2);
        @signal[hostA_sentPk];
        @delegatesignal[sentPk2](source=hostA.udpApp[0].sentPk; target=hostA_sentPk);


    submodules:
        visualizer: <default("IntegratedCanvasVisualizer")> like IIntegratedVisualizer if hasVisualizer() {
            @display("p=580,125");
        }
        configurator: IPv4NetworkConfigurator {
            @display("p=580,200");
        }
        radioMedium: <mediumType> like IRadioMedium {
            @display("p=580,275");
        }
        figureHelper: DelegateSignalConfigurator {
            @display("p=580,350");
        }
        hostA: <hostType> like INetworkNode {
            @display("p=52.416,413.28");
        }
        hostB: <hostType> like INetworkNode {
            @display("p=531.216,325.584");
        }
        hostC: <hostType> like INetworkNode {
            @display("p=52.416,191.52");
        }
}

//##### (marker for doxygen)

