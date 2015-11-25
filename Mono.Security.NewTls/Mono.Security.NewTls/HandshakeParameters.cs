using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	using X509;
	using Cipher;
	using Extensions;

	internal class HandshakeParameters : DisposeContext
	{
		SecureBuffer clientRandom;
		SecureBuffer serverRandom;
		SecureBuffer sessionId;

		KeyExchange keyExchange;

		HandshakeHash handshakeMessages;
		TlsExtensionCollection requestedExtensions;
		TlsExtensionCollection activeExtensions;
		CipherSuiteCollection supportedCiphers;

		internal const long  UNIX_BASE_TICKS = 621355968000000000;

		internal int GetUnixTime ()
		{
			DateTime now = DateTime.UtcNow;

			return (int)((now.Ticks - UNIX_BASE_TICKS) / TimeSpan.TicksPerSecond);
		}

		internal HandshakeHash HandshakeMessages {
			get { return handshakeMessages; }
			set { handshakeMessages = Add (value); }
		}

		internal CipherSuiteCollection SupportedCiphers {
			get { return supportedCiphers; }
			set { supportedCiphers = value; }
		}

		internal TlsExtensionCollection RequestedExtensions {
			get {
				if (requestedExtensions == null)
					requestedExtensions = new TlsExtensionCollection ();
				return requestedExtensions;
			}
		}

		internal TlsExtensionCollection ActiveExtensions {
			get {
				if (activeExtensions == null)
					activeExtensions = new TlsExtensionCollection ();
				return activeExtensions;
			}
		}

		internal SecureBuffer ClientRandom {
			get { return clientRandom; }
			set { clientRandom = Add (value); }
		}

		internal SecureBuffer ServerRandom {
			get { return serverRandom; }
			set { serverRandom = Add (value); }
		}

		internal SecureBuffer SessionId {
			get { return sessionId; }
			set { sessionId = Add (value); }
		}

		internal KeyExchange KeyExchange {
			get { return keyExchange; }
			set { keyExchange = Add (value); }
		}

		internal bool RequestedSecureNegotiation {
			get; set;
		}

		internal bool SecureNegotiationSupported {
			get; set;
		}

		protected override void Clear ()
		{
			base.Clear ();
			requestedExtensions = null;
		}
	}
}

