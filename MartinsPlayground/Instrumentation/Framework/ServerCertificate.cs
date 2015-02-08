using System;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class ServerCertificate : CertificateAndKeyAsPFX
	{
		public ServerCertificate (byte[] data, string password)
			: base (data, password)
		{
		}
		
	}
}

