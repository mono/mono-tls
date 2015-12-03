using System;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoDefaultHttpSettings : IDefaultHttpSettings
	{
		public bool InstallDefaultCertificateValidator {
			get { return false; }
		}

		public ISslStreamProvider DefaultSslStreamProvider {
			get {
				throw new NotImplementedException ();
			}
		}
	}
}

