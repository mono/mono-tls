using System;
using System.Text;

namespace Mono.Security.Protocol.NewTls.Handshake
{
	using X509;

	class TlsCertificateRequest : HandshakeMessage
	{
		public TlsCertificateRequest (ClientCertificateParameters parameters)
			: base (HandshakeType.CertificateRequest)
		{
			Parameters = parameters;
		}

		public TlsCertificateRequest (TlsBuffer incoming)
			: base (HandshakeType.CertificateRequest)
		{
			Parameters = new ClientCertificateParameters ();
			Read (incoming);
		}

		public ClientCertificateParameters Parameters {
			get;
			private set;
		}

		protected override void Encode (TlsStream stream)
		{
			stream.Write ((byte)Parameters.CertificateTypes.Count);
			for (int i = 0; i < Parameters.CertificateTypes.Count; i++)
				stream.Write ((byte)Parameters.CertificateTypes [i]);
			stream.Write ((short)(Parameters.SignatureAndHashAlgorithms.Count * 2));
			for (int i = 0; i < Parameters.SignatureAndHashAlgorithms.Count; i++)
				Parameters.SignatureAndHashAlgorithms [i].Encode (stream);

			var startPos = stream.Position;
			stream.Write ((short)0);
			foreach (var issuer in Parameters.CertificateAuthorities) {
				var bytes = X501.FromString (issuer).GetBytes ();
				stream.Write ((short)bytes.Length);
				stream.Write (bytes);
			}
			var endPos = stream.Position;
			stream.Position = startPos;
			stream.Write ((short)(endPos - startPos - 2));
			stream.Position = endPos;
		}

		protected override void Read (TlsBuffer incoming)
		{
			var length = incoming.ReadByte ();
			for (int i = 0; i < length; i++)
				Parameters.CertificateTypes.Add ((ClientCertificateType)incoming.ReadByte ());

			var length2 = incoming.ReadInt16 ();
			if ((length2 % 2) != 0)
				throw new TlsException (AlertDescription.IlegalParameter);
			var signatureTypes = new SignatureAndHashAlgorithm [length2 >> 1];
			for (int i = 0; i < signatureTypes.Length; i++)
				Parameters.SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (incoming));

			var length3 = incoming.ReadInt16 ();
			if (incoming.Remaining != length3)
				throw new TlsException (AlertDescription.DecodeError);

			/*
			 * Read requested certificate authorities (Distinguised Names)
			 *
			 * Name ::= SEQUENCE OF RelativeDistinguishedName
			 *
			 * RelativeDistinguishedName ::= SET OF AttributeValueAssertion
			 *
			 * AttributeValueAssertion ::= SEQUENCE {
			 *     attributeType OBJECT IDENTIFIER
			 *     attributeValue ANY
			 * }
			 *
			 */

			while (incoming.Remaining > 0) {
				var rdn = new ASN1 (incoming.ReadBytes (incoming.ReadInt16 ()));
				Parameters.CertificateAuthorities.Add (X501.ToString (rdn));
			}
		}
	}
}

