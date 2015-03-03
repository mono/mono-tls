using System;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.Instrumentation.Resources
{
	using Framework;

	class ServerCertificateFromCA : ServerCertificate
	{
		internal ServerCertificateFromCA ()
			: base (ResourceManager.ReadResource ("CA.server-cert.pfx"), "monkey")
		{
		}
	}
}

