using System;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.Instrumentation.Resources
{
	using Framework;

	class MonkeyCertificate : ClientCertificate
	{
		internal MonkeyCertificate ()
			: base (ResourceManager.ReadResource ("CA.monkey.pfx"), "monkey")
		{
		}
	}
}

