using System;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace SnmpLib
{
    public class SimpleSNMP
    {
        public static void Main(string[] argv)
        {
			var conn = new SNMP();

			conn.SendPacket();
        }
    }

    public class SNMP
    {
		public SNMP() { }

		public void SendPacket()
		{
			try
			{
				var pkt = GetHardPacket();

				SendUDPPacket(pkt, 162);
			}
			catch (Exception ex)
			{
				throw;
			}
		}

		private byte[] GetHardPacket()
		{
            var packet = new byte[44];
            var pos = 0;

			/*from packet sniffer
			0x30, 0x2a, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa4, 0x1d, 0x06,
			0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x04, 0x01, 0x02, 0x15, 0x40, 0x04, 0x7f, 0x00, 0x00, 0x01,
			0x02, 0x01, 0x06, 0x02, 0x01, 0x00, 0x43, 0x02, 0x3b, 0xda, 0x30, 0x00
			*/

			//Sequence
			packet[pos++] = 0x30;	//0 start
			packet[pos++] = 0x2a;	//1 length 42
			//Version
			packet[pos++] = 0x02;	//2 integer type
			packet[pos++] = 0x01;	//3 length
			packet[pos++] = 0x00;	//4 version
			//Community
			packet[pos++] = 0x04;	//5 string type
			packet[pos++] = 0x06;	//6 length
			packet[pos++] = 0x70;	//7  p
			packet[pos++] = 0x75;	//8  u
			packet[pos++] = 0x62;	//9  b
			packet[pos++] = 0x6c;	//10 l
			packet[pos++] = 0x69;	//11 i
			packet[pos++] = 0x63;	//12 c
			//PDU
			packet[pos++] = 0xa4;	//13 pdu type
			packet[pos++] = 0x2b;	//14 request id
			packet[pos++] = 0x06;	//15 error status
			packet[pos++] = 0x09;	//16 error index

			packet[pos++] = 0x2b;	//17 enterprise
			packet[pos++] = 0x06;	//18 |
			packet[pos++] = 0x01;	//19 |
			packet[pos++] = 0x04;	//20 |
			packet[pos++] = 0x01;	//21 |
			packet[pos++] = 0x04;	//22 |
			packet[pos++] = 0x01;	//23 |
			packet[pos++] = 0x02;	//24 |
			packet[pos++] = 0x15;	//25 enterprise

			packet[pos++] = 0x40;	//26 agentaddr type
			packet[pos++] = 0x04;	//27 length
			packet[pos++] = 0xc0;	//28 192
			packet[pos++] = 0xa8;	//29 .168
			packet[pos++] = 0x00;	//30 .0
			packet[pos++] = 0x01;	//31 .1 
			//packet[pos++] = 0x7f;	//28 127 
			//packet[pos++] = 0x00;	//29 .0
			//packet[pos++] = 0x00;	//30 .0
			//packet[pos++] = 0x01;	//31 .1 

			packet[pos++] = 0x02;	//32 integer type
			packet[pos++] = 0x01;	//33 length
			packet[pos++] = 0x06;	//34 generic trap (int) coldStart(0), warmStart(1),linkDown(2),linkUp(3),authenticationFailure(4),egpNeighborLoss(5),enterpriseSpecific(6)

			packet[pos++] = 0x02;	//35 integer type
			packet[pos++] = 0x01;	//36 length
			packet[pos++] = 0x01;	//37 specific trap (int)

			packet[pos++] = 0x43;	//38 timestamp type
			packet[pos++] = 0x02;	//39 length
			packet[pos++] = 0x3b;	//40 15322 ticks
			packet[pos++] = 0xda;	//41 
			// variable Bindings
			packet[pos++] = 0x05;	//42 type
			packet[pos++] = 0x00;	//43 length
			
			return packet;		
		}

		private byte[] SendUDPPacket(byte[] packet, int port)
		{
			Socket socket = null;

			try
			{
				socket = new Socket(
							AddressFamily.InterNetwork,
							SocketType.Dgram,
							ProtocolType.Udp);

				socket.SetSocketOption(
								SocketOptionLevel.Socket,
								SocketOptionName.ReceiveTimeout,
								2000);

				var hostEntry = Dns.Resolve(SnmpKeys.RECEIVER_IP);

				var endPoint = new IPEndPoint(hostEntry.AddressList[0], port);

				socket.SendTo(packet, packet.Length, SocketFlags.None, endPoint);
			}
			catch (SocketException se)
			{
				packet[0] = 0xff;
			}
			finally
			{
				if(socket != null)
					socket.Dispose();
			}

			return packet;
		}
	}
}