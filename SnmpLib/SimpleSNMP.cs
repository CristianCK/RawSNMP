using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace SnmpLib
{
    public class SimpleSNMP
    {
		public SimpleSNMP() { }

		public void SendUdpPackets()
		{
			HardPackets = new Dictionary<PacketType, byte[]>();

			HardPackets.Add(
				PacketType.TrapV1, GetTrapV1());
			HardPackets.Add(
				PacketType.TrapV2, GetTrapV2());

			Send(
				HardPackets[PacketType.TrapV1], 162);
			Send(
				HardPackets[PacketType.TrapV2], 162);
		}

		public bool Send(byte[] packet, int port)
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

				return true;
			}
			catch (SocketException)
			{
				return false;
			}
			finally
			{
				if (socket != null)
					socket.Dispose();
			}
		}

		protected Dictionary<PacketType, byte[]> HardPackets { get; private set; }

		protected enum PacketType {
										TrapV1 = 1,
										TrapV2 = 2,
										InformV2 = 3
									};

		#region Private
		private byte[] GetTrapV1()
		{
			var packet = new byte[44];
			var pos = 0;

			/*
			0x30, 0x2a, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa4, 0x1d, 0x06,
			0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x04, 0x01, 0x02, 0x15, 0x40, 0x04, 0x7f, 0x00, 0x00, 0x01,
			0x02, 0x01, 0x06, 0x02, 0x01, 0x00, 0x43, 0x02, 0x3b, 0xda, 0x30, 0x00
			*/

			//Sequence
			packet[pos++] = 0x30;	//0 start
			packet[pos++] = 0x2a;	//1 size
			//Version
			packet[pos++] = 0x02;	//2 integer type
			packet[pos++] = 0x01;	//3 length
			packet[pos++] = 0x00;	//4 version
			//Community
			packet[pos++] = 0x04;	//5 string type
			packet[pos++] = 0x06;	//6 length
			packet[pos++] = 0x70;	//7  'p'
			packet[pos++] = 0x75;	//8  'u'
			packet[pos++] = 0x62;	//9  'b'
			packet[pos++] = 0x6c;	//10 'l'
			packet[pos++] = 0x69;	//11 'i'
			packet[pos++] = 0x63;	//12 'c'
			//Message
			packet[pos++] = 0xa4;	//13 type = trap
			packet[pos++] = 0x2b;	//14 0x1d;
			packet[pos++] = 0x06;	//15
			packet[pos++] = 0x09;	//16
			packet[pos++] = 0x2b;	//17 enterprise
			packet[pos++] = 0x06;	//18 |
			packet[pos++] = 0x01;	//19 |
			packet[pos++] = 0x04;	//20 |
			packet[pos++] = 0x01;	//21 |
			packet[pos++] = 0x04;	//22 |
			packet[pos++] = 0x01;	//23 |
			packet[pos++] = 0x02;	//24 |
			packet[pos++] = 0x15;	//25 enterprise
			packet[pos++] = 0x40;	//26 ?
			packet[pos++] = 0x04;	//27 ?
			packet[pos++] = 0x7f;	//28 127 agent-addr
			packet[pos++] = 0x00;	//29 .0
			packet[pos++] = 0x00;	//30 .0
			packet[pos++] = 0x01;	//31 .1 
			packet[pos++] = 0x02;	//32 ?
			packet[pos++] = 0x01;	//33 ?
			packet[pos++] = 0x06;	//34 generic-trap
			packet[pos++] = 0x02;	//35 ?
			packet[pos++] = 0x01;	//36 ?
			packet[pos++] = 0x01;	//37 specific-trap
			packet[pos++] = 0x43;	//38 ?
			packet[pos++] = 0x02;	//39 ?
			packet[pos++] = 0x3b;	//40 time-stamp: 15322
			packet[pos++] = 0xda;	//41 time-stamp: 15322
			packet[pos++] = 0x30;	//42
			packet[pos++] = 0x00;	//43

			return packet;
		}

		private byte[] GetTrapV2()
		{
			var packet = new byte[69];
			var pos = 0;

			/*
			0x30 0x43 0x02 0x01 0x01 0x04 0x06 0x70 0x75 0x62 0x6c 0x69 0x63 0xa7 0x36 0x02
			0x04 0x32 0x45 0xa0 0xd0 0x02 0x01 0x00 0x02 0x01 0x00 0x30 0x28 0x30 0x0d 0x06
			0x08 0x2b 0x06 0x01 0x02 0x01 0x01 0x03 0x00 0x43 0x01 0x00 0x30 0x17 0x06 0x0a
			0x2b 0x06 0x01 0x06 0x03 0x01 0x01 0x04 0x01 0x00 0x06 0x09 0x2b 0x06 0x01 0x06
			0x03 0x01 0x01 0x05 0x01
			*/

			//Sequence
			packet[pos++] = 0x30; // 0 start
			packet[pos++] = 0x43; // 1 size
			//Version
			packet[pos++] = 0x02; // 2 integer type
			packet[pos++] = 0x01; // 3 length
			packet[pos++] = 0x01; // 4 version
			//Community
			packet[pos++] = 0x04; // 5 string type
			packet[pos++] = 0x06; // 6 length
			packet[pos++] = 0x70; // 7  'p'
			packet[pos++] = 0x75; // 8  'u'
			packet[pos++] = 0x62; // 9  'b'
			packet[pos++] = 0x6c; // 10 'l'
			packet[pos++] = 0x69; // 11 'i'
			packet[pos++] = 0x63; // 12 'c'
			//Message
			packet[pos++] = 0xa7; // 13 type = trap
			packet[pos++] = 0x36; // 14 

			packet[pos++] = 0x02; // 15
			packet[pos++] = 0x04; // 16
			//  request-id
			packet[pos++] = 0x32; // 17
			packet[pos++] = 0x45; // 18
			packet[pos++] = 0xa0; // 10
			packet[pos++] = 0xd0; // 20
			//  error-status
			packet[pos++] = 0x02; // 21 integer type 
			packet[pos++] = 0x01; // 22 length
			packet[pos++] = 0x00; // 23 noError
			// error-index
			packet[pos++] = 0x02; // 24  integer type 
			packet[pos++] = 0x01; // 25  length
			packet[pos++] = 0x00; // 26 errorIndex
			// variable-bindings
			packet[pos++] = 0x30; // 27
			packet[pos++] = 0x28; // 28 

			packet[pos++] = 0x30; // 29
			packet[pos++] = 0x0d; // 30
			packet[pos++] = 0x06; // 31 
			packet[pos++] = 0x08; // 32
			packet[pos++] = 0x2b; // 33
			packet[pos++] = 0x06; // 34 
			packet[pos++] = 0x01; // 35 
			packet[pos++] = 0x02; // 36
			packet[pos++] = 0x01; // 37
			packet[pos++] = 0x01; // 38
			packet[pos++] = 0x03; // 39
			packet[pos++] = 0x00; // 40
			packet[pos++] = 0x43; // 41
			packet[pos++] = 0x01; // 42
			packet[pos++] = 0x00; // 43

			packet[pos++] = 0x30; // 44 
			packet[pos++] = 0x17; // 45
			packet[pos++] = 0x06; // 46
			packet[pos++] = 0x0a; // 47
			packet[pos++] = 0x2b; // 48
			packet[pos++] = 0x06; // 49
			packet[pos++] = 0x01; // 50
			packet[pos++] = 0x06; // 51
			packet[pos++] = 0x03; // 52
			packet[pos++] = 0x01; // 53
			packet[pos++] = 0x01; // 54
			packet[pos++] = 0x04; // 55
			packet[pos++] = 0x01; // 56
			packet[pos++] = 0x00; // 57
			packet[pos++] = 0x06; // 58
			packet[pos++] = 0x09; // 59
			packet[pos++] = 0x2b; // 60
			packet[pos++] = 0x06; // 61
			packet[pos++] = 0x01; // 62
			packet[pos++] = 0x06; // 63
			packet[pos++] = 0x03; // 64
			packet[pos++] = 0x01; // 65
			packet[pos++] = 0x01; // 66
			packet[pos++] = 0x05; // 67
			packet[pos++] = 0x01; // 68

			return packet;
		}
		#endregion
	}
}