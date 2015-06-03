using System;
using System.Security.Cryptography;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Handshake
{
	using Cipher;

	class TlsServerKeyExchange : HandshakeMessage
	{
		public TlsServerKeyExchange (TlsContext context, TlsBuffer incoming)
			: base (HandshakeType.ServerKeyExchange)
		{
			KeyExchange = KeyExchange.Create (context.NegotiatedProtocol, context.Session.PendingCrypto.Cipher.ExchangeAlgorithmType);
			Read (incoming);
		}

		public TlsServerKeyExchange (KeyExchange keyExchange)
			: base (HandshakeType.ServerKeyExchange)
		{
			KeyExchange = keyExchange;
		}

		public KeyExchange KeyExchange {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			KeyExchange.ReadServer (incoming);

			if (incoming.Remaining != 0)
				throw new TlsException (AlertDescription.DecodeError);
		}

		protected override void Encode (TlsStream stream)
		{
			KeyExchange.WriteServer (stream);
		}
	}
}

