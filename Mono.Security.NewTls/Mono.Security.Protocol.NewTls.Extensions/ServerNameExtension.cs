using System;
using System.Net;
using System.Text;

namespace Mono.Security.Protocol.NewTls.Extensions
{
	public class ServerNameExtension : TlsExtension
	{
		public override ExtensionType ExtensionType {
			get { return ExtensionType.ServerName; }
		}

		public string ServerName {
			get;
			private set;
		}

		public ServerNameExtension (TlsBuffer incoming)
		{
			var length = incoming.ReadInt16 ();
			if (length != incoming.Remaining)
				throw new TlsException (AlertDescription.DecodeError);
			var type = incoming.ReadByte ();
			if (type != 0x00)
				throw new TlsException (AlertDescription.IlegalParameter, "Unknown NameType in ServerName extension");
			var nameLength = incoming.ReadInt16 ();
			if (nameLength + 3 != length)
				throw new TlsException (AlertDescription.DecodeError);
			ServerName = Encoding.ASCII.GetString (incoming.ReadBytes (nameLength));
		}

		public ServerNameExtension (string host)
		{
			if (!IsLegalHostName (host))
				throw new InvalidOperationException ();
			ServerName = host;
		}

		internal static bool IsLegalHostName (string host)
		{
			if (string.IsNullOrEmpty (host))
				return false;
			IPAddress addr;
			if (IPAddress.TryParse (host, out addr))
				return false;
			return true;
		}

		public override void Encode (TlsBuffer buffer)
		{
			var asciiName = Encoding.ASCII.GetBytes (ServerName);

			buffer.Write ((short)ExtensionType);
			buffer.Write ((short)(asciiName.Length + 5)); // ServerNameList
			buffer.Write ((short)(asciiName.Length + 3)); // ServerList
			buffer.Write ((byte)0x00); // HostName
			buffer.Write ((short)asciiName.Length);
			buffer.Write (asciiName);
		}

		public override bool ProcessClient (TlsContext context)
		{
			return false;
		}

		public override TlsExtension ProcessServer (TlsContext context)
		{
			return null;
		}
	}
}

