using System;

namespace Mono.Security.NewTls.Handshake
{
	using X509;

	class TlsCertificate : HandshakeMessage
	{
		public TlsCertificate (X509CertificateCollection certificates)
			: base (HandshakeType.Certificate)
		{
			Certificates = certificates;
		}

		public TlsCertificate (TlsBuffer incoming)
			: base (HandshakeType.Certificate)
		{
			Certificates = new X509CertificateCollection ();
			Read (incoming);
		}

		public X509CertificateCollection Certificates {
			get;
			private set;
		}

		protected override void Read (TlsBuffer incoming)
		{
			var length = incoming.ReadInt24 ();
			var endOffset = incoming.Position + length;

			while (incoming.Position < endOffset) {
				var certLength = incoming.ReadInt24 ();
				if (certLength == 0)
					break;

				var buffer = incoming.ReadBytes (certLength);

				// Create a new X509 Certificate
				var certificate = new X509Certificate (buffer);
				Certificates.Add (certificate);
			}

			if (incoming.Position != endOffset || incoming.Remaining != 0)
				throw new TlsException (AlertDescription.DecodeError);

		}

		protected override void Encode (TlsStream stream)
		{
			var startPosition = stream.Position;
			stream.WriteInt24 (-1);

			foreach (var certificate in Certificates) {
				var data = certificate.RawData;

				stream.WriteInt24 (data.Length);
				stream.Write (data);
			}

			var endPosition = stream.Position;
			stream.Position = startPosition;
			stream.WriteInt24 ((int)(endPosition - startPosition - 3));
			stream.Position = endPosition;
		}
	}
}
