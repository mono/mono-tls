using System;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	public sealed class ServerCertificate : CertificateAndKeyAsPFX, IServerCertificate
	{
		public ServerCertificate (byte[] data, string password)
			: base (data, password)
		{
		}

		public ServerCertificate (IServerCertificate certificate)
			: base (certificate.Data, certificate.Password)
		{
		}
	}
}

