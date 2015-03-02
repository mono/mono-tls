using System;
using Mono.Security.Cryptography;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Handshake
{
	class TlsFinished : HandshakeMessage
	{
		public TlsFinished (TlsBuffer incoming)
			: base (HandshakeType.Finished)
		{
			Read (incoming);
		}

		public TlsFinished (SecureBuffer hash)
			: base (HandshakeType.Finished)
		{
			Hash = hash;
		}

		public SecureBuffer Hash {
			get;
			private set;
		}

		internal const string ClientSeed = "client finished";
		internal const string ServerSeed = "server finished";

		protected override void Read (TlsBuffer incoming)
		{
			Hash = new SecureBuffer (incoming.ReadBytes (12));
			if (incoming.Remaining != 0)
				throw new TlsException (AlertDescription.DecodeError);
		}

		protected override void Encode (TlsStream stream)
		{
			stream.Write (Hash.Buffer);
		}
	}
}

