using System;

namespace Mono.Security.NewTls.Handshake
{
	using Extensions;
	using Cipher;

	class TlsServerHello : HandshakeMessage
	{
		public TlsServerHello (TlsContext context, TlsBuffer incoming)
			: base (HandshakeType.ServerHello)
		{
			// Read and verify protocol version
			ServerProtocol = (TlsProtocolCode)incoming.ReadInt16 ();
			context.VerifyServerProtocol (ServerProtocol);

			Read (incoming);
		}

		public TlsServerHello (TlsProtocolCode protocol, SecureBuffer random, SecureBuffer session, CipherSuiteCode cipher, TlsExtensionCollection extensions)
			: base (HandshakeType.ServerHello)
		{
			ServerProtocol = protocol;
			ServerRandom = random;
			SessionID = session;
			SelectedCipher = cipher;
			Extensions = extensions;
		}

		public TlsProtocolCode ServerProtocol {
			get;
			private set;
		}

		public SecureBuffer ServerRandom {
			get;
			private set;
		}

		public SecureBuffer SessionID {
			get;
			private set;
		}

		public CipherSuiteCode SelectedCipher {
			get;
			private set;
		}

		public TlsExtensionCollection Extensions {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			// Server random
			ServerRandom = new SecureBuffer (incoming.ReadBytes (32));

			// Session ID
			var sessionIdLength = (int)incoming.ReadByte ();
			if (sessionIdLength > 0) {
				SessionID = new SecureBuffer (incoming.ReadBytes (sessionIdLength));
			}

			// Cipher suite
			SelectedCipher = (CipherSuiteCode)incoming.ReadInt16 ();

			var compressionMethod = incoming.ReadByte ();
			if (compressionMethod != 0)
				throw new TlsException (AlertDescription.IlegalParameter, "Invalid compression method received from server");

			Extensions = new TlsExtensionCollection (incoming);
		}

		protected override void Encode (TlsStream stream)
		{
			stream.Write ((short)ServerProtocol);
			stream.Write (ServerRandom.Buffer);

			if (SessionID != null) {
				stream.Write ((byte)SessionID.Size);
				stream.Write (SessionID.Buffer);
			} else {
				stream.Write ((byte)0);
			}

			stream.Write ((short)SelectedCipher);

			stream.Write ((byte)0);

			Extensions.Write (stream);
		}
	}
}

