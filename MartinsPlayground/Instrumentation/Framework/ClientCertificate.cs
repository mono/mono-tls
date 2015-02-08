using System;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class ClientCertificate : CertificateAndKeyAsPFX
	{
		public ClientCertificate (byte[] data, string password)
			: base (data, password)
		{
		}

	}
}

