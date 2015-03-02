using System;

namespace Mono.Security.NewTls.Handshake
{
	class TlsHelloRequest : HandshakeMessage
	{
		public TlsHelloRequest ()
			: base (HandshakeType.HelloRequest)
		{
		}

		protected override void Encode (TlsStream stream)
		{
		}

		protected override void Read (TlsBuffer incoming)
		{
			if (incoming.Remaining != 0)
				throw new TlsException (AlertDescription.DecodeError);
		}
	}
}

