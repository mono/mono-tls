using System;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	class SelfSignedServerCertificate : IServerCertificate
	{
		public byte[] Data {
			get;
			private set;
		}

		public string Password {
			get;
			private set;
		}

		internal SelfSignedServerCertificate ()
		{
			Data = ResourceManager.ReadResource ("CA.server-self.pfx");
			Password = "monkey";
		}
	}
}

