using System;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	class MonkeyCertificate : IClientCertificate
	{
		public byte[] Data {
			get;
			private set;
		}

		public string Password {
			get;
			private set;
		}

		internal MonkeyCertificate ()
		{
			Password = "monkey";
			Data = ResourceManager.ReadResource ("CA.monkey.pfx");
		}
	}
}

