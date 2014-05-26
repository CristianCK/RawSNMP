using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnmpLib
{
	public class MainClass
	{
		public static void Main(string[] argv)
		{
			var conn = new SimpleSNMP();

			conn.SendUdpPackets();
		}
	}
}