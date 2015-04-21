using System;
using System.Collections.Generic;

namespace Mono.Security.NewTls
{
	public class ClientCertificateParameters
	{
		List<ClientCertificateType> certificateTypes;
		List<SignatureAndHashAlgorithm> signatureTypes;
		List<string> certificateAuthorities;

		public IList<ClientCertificateType> CertificateTypes {
			get {
				if (certificateTypes == null)
					certificateTypes = new List<ClientCertificateType> ();
				return certificateTypes;
			}
		}

		public IList<SignatureAndHashAlgorithm> SignatureAndHashAlgorithms {
			get {
				if (signatureTypes == null)
					signatureTypes = new List<SignatureAndHashAlgorithm> ();
				return signatureTypes;
			}
		}

		public IList<string> CertificateAuthorities {
			get {
				if (certificateAuthorities == null)
					certificateAuthorities = new List<string> ();
				return certificateAuthorities;
			}
		}

		public void EnsureDefaultValues ()
		{
			// FIXME: Provide better default values
			if (CertificateTypes.Count == 0)
				CertificateTypes.Add (ClientCertificateType.RsaSign);
			if (SignatureAndHashAlgorithms.Count == 0) {
				SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (HashAlgorithmType.Sha512, SignatureAlgorithmType.Rsa));
				SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (HashAlgorithmType.Sha384, SignatureAlgorithmType.Rsa));
				SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa));
				SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (HashAlgorithmType.Sha1, SignatureAlgorithmType.Rsa));
			}
		}

		public static ClientCertificateParameters GetDefaultParameters ()
		{
			var defaultParameters = new ClientCertificateParameters ();
			defaultParameters.EnsureDefaultValues ();
			return defaultParameters;
		}
	}
}

