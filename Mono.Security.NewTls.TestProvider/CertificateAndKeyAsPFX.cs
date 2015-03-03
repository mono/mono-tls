using System;
using System.Security.Cryptography.X509Certificates;

namespace Mono.Security.NewTls.TestProvider
{
	public class CertificateAndKeyAsPFX : PrivateFile
	{
		public X509Certificate2 Certificate {
			get;
			private set;
		}

		public CertificateAndKeyAsPFX (byte[] data, string password)
			: base (data, password)
		{
			Certificate = new X509Certificate2 (data, password);
		}
	}
}

