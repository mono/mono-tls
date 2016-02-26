using System;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Handshake
{
	class TlsServerHelloDone : HandshakeMessage
	{
		public TlsServerHelloDone ()
			: base (HandshakeType.ServerHelloDone)
		{
		}

		protected override void Read (TlsBuffer incoming)
		{
			if (incoming.Remaining != 0)
				throw new TlsException (AlertDescription.DecodeError);
		}

		protected override void Encode (TlsStream stream)
		{
		}
	}
}

