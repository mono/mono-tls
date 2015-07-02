using System;
using System.Text;

namespace Mono.Security.NewTls.Handshake
{
	using X509;

	class TlsCertificateRequest : HandshakeMessage
	{
		public TlsProtocolCode Protocol {
			get;
			private set;
		}

		public TlsCertificateRequest (TlsProtocolCode protocol, ClientCertificateParameters parameters)
			: base (HandshakeType.CertificateRequest)
		{
			Protocol = protocol;
			Parameters = parameters;
		}

		public TlsCertificateRequest (TlsProtocolCode protocol, TlsBuffer incoming)
			: base (HandshakeType.CertificateRequest)
		{
			Protocol = protocol;
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

			if (Protocol == TlsProtocolCode.Tls12) {
				var count = Parameters.HasSignatureParameters ? Parameters.SignatureParameters.SignatureAndHashAlgorithms.Count : 0;
				stream.Write ((short)(count * 2));
				for (int i = 0; i < count; i++)
					Parameters.SignatureParameters.SignatureAndHashAlgorithms [i].Encode (stream);
			}

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

			if (Protocol == TlsProtocolCode.Tls12) {
				var length2 = incoming.ReadInt16 ();
				if ((length2 % 2) != 0)
					throw new TlsException (AlertDescription.IlegalParameter);
				var signatureTypes = new SignatureAndHashAlgorithm [length2 >> 1];
				for (int i = 0; i < signatureTypes.Length; i++)
					Parameters.SignatureParameters.SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (incoming));
			}

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

