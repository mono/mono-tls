using System;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	public abstract class ClientCertificate : CertificateAndKeyAsPFX, IClientCertificate
	{
		public ClientCertificate (byte[] data, string password)
			: base (data, password)
		{
		}

	}
}

