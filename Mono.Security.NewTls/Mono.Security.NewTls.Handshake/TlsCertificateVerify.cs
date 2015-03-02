using System;

namespace Mono.Security.NewTls.Handshake
{
	using Cipher;

	class TlsCertificateVerify : HandshakeMessage
	{
		public TlsCertificateVerify (SignatureAndHashAlgorithm algorithm, SecureBuffer signature)
			: base (HandshakeType.CertificateVerify)
		{
			Algorithm = algorithm;
			Signature = signature;
		}

		public TlsCertificateVerify (TlsBuffer incoming)
			: base (HandshakeType.CertificateVerify)
		{
			Read (incoming);
		}

		public SignatureAndHashAlgorithm Algorithm {
			get;
			private set;
		}

		public SecureBuffer Signature {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			Algorithm = new SignatureAndHashAlgorithm (incoming);
			Signature = incoming.ReadSecureBuffer (incoming.ReadInt16 ());
		}

		protected override void Encode (TlsStream stream)
		{
			Algorithm.Encode (stream);
			stream.Write ((short)Signature.Size);
			stream.Write (Signature.Buffer);
		}
	}
}

