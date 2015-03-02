using System;
using System.Security.Cryptography;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Handshake
{
	using Cipher;

	class TlsClientKeyExchange : HandshakeMessage
	{
		public TlsClientKeyExchange (TlsContext context, TlsBuffer incoming)
			: base (HandshakeType.ClientKeyExchange)
		{
			KeyExchange = KeyExchange.Create (context.Session.PendingCrypto.Cipher.ExchangeAlgorithmType);
			Read (incoming);
		}

		public TlsClientKeyExchange (KeyExchange keyExchange)
			: base (HandshakeType.ClientKeyExchange)
		{
			KeyExchange = keyExchange;
		}

		public KeyExchange KeyExchange {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			KeyExchange.ReadClient (incoming);
		}

		protected override void Encode (TlsStream stream)
		{
			KeyExchange.WriteClient (stream);
		}
	}
}

