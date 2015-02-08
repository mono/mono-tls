using System;
using System.Collections.Generic;

namespace Mono.Security.Protocol.NewTls.Handshake
{
	using Extensions;
	using Cipher;

	internal class TlsClientHello : HandshakeMessage
	{
		public TlsClientHello (TlsContext context, TlsBuffer incoming)
			: base (HandshakeType.ClientHello)
		{
			// FIXME: Fallback
			ClientProtocol = (TlsProtocolCode)incoming.ReadInt16 ();
			context.VerifyServerProtocol (ClientProtocol);

			Read (incoming);
		}

		public TlsClientHello (TlsProtocolCode protocol, SecureBuffer random, SecureBuffer session, CipherSuiteCode[] ciphers, TlsExtensionCollection extensions)
			: base (HandshakeType.ClientHello)
		{
			ClientProtocol = protocol;
			ClientRandom = random;
			SessionID = session;
			ClientCiphers = ciphers;
			Extensions = extensions;
		}

		public TlsProtocolCode ClientProtocol {
			get;
			private set;
		}

		public SecureBuffer ClientRandom {
			get;
			private set;
		}

		public SecureBuffer SessionID {
			get;
			private set;
		}

		public CipherSuiteCode[] ClientCiphers {
			get;
			private set;
		}

		public TlsExtensionCollection Extensions {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			ClientRandom = new SecureBuffer (incoming.ReadBytes (32));

			var length = (short)incoming.ReadByte ();
			SessionID = new SecureBuffer (incoming.ReadBytes (length));

			length = incoming.ReadInt16 ();
			if ((length % 2) != 0)
				throw new TlsException (AlertDescription.DecodeError);

			bool seenSCSV = false;
			ClientCiphers = new CipherSuiteCode [length >> 1];
			for (int i = 0; i < ClientCiphers.Length; i++) {
				ClientCiphers [i] = (CipherSuiteCode)incoming.ReadInt16 ();
				if (ClientCiphers [i] == CipherSuiteCode.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
					seenSCSV = true;
			}

			// Compression methods
			length = incoming.ReadByte ();
			incoming.Position += length;

			Extensions = new TlsExtensionCollection (incoming);

			if (seenSCSV)
				Extensions.AddRenegotiationExtension ();
		}

		protected override void Encode (TlsStream stream)
		{
			// requested client version
			stream.Write ((short)ClientProtocol);

			// Random bytes - Unix time + Radom bytes [28]
			stream.Write (ClientRandom.Buffer);

			// Session id
			if (SessionID != null) {
				stream.Write ((byte)SessionID.Size);
				stream.Write (SessionID.Buffer);
			} else {
				stream.Write ((byte)0);
			}

			// Write Supported Cipher suites
			stream.Write ((short)(ClientCiphers.Length * 2));
			for (int i = 0; i < ClientCiphers.Length; i++)
				stream.Write ((short)ClientCiphers [i]);

			// Compression methods length
			stream.Write((byte)1);

			// Compression methods ( 0 = none )
			stream.Write ((byte)0);

			Extensions.Write (stream);
		}
	}
}

