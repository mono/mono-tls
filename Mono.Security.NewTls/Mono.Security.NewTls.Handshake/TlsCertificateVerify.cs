using System;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Handshake
{
	using Cipher;

	class TlsCertificateVerify : HandshakeMessage
	{
		public TlsCertificateVerify (Signature signature)
			: base (HandshakeType.CertificateVerify)
		{
			Signature = signature;
		}

		public TlsCertificateVerify (TlsProtocolCode protocol, TlsBuffer incoming)
			: base (HandshakeType.CertificateVerify)
		{
			Protocol = protocol;
			Read (incoming);
		}

		public TlsProtocolCode Protocol {
			get;
			private set;
		}

		public Signature Signature {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			Signature = Signature.Read (Protocol, incoming);
		}

		protected override void Encode (TlsStream stream)
		{
			Signature.Write (stream);
		}
	}
}

