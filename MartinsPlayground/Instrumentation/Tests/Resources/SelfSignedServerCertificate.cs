using System;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.Instrumentation.Resources
{
	using Framework;

	class SelfSignedServerCertificate : ServerCertificate
	{
		internal SelfSignedServerCertificate ()
			: base (ResourceManager.ReadResource ("CA.server-self.pfx"), "monkey")
		{
		}
	}
}

