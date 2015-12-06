using System;
using System.Net;
using System.Threading;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Server;

using Mono.Security.Interface;

[assembly: DependencyProvider (typeof (Mono.Security.NewTls.TestFramework.TestFrameworkDependencyProvider))]

namespace Mono.Security.NewTls.TestFramework
{
	using MonoConnectionFramework;

	public class TestFrameworkDependencyProvider : IDefaultConnectionSettings, IDependencyProvider
	{
		public void Initialize ()
		{
			var monoFactory = new MonoConnectionProviderFactory ();
			DependencyInjector.RegisterDependency<MonoConnectionProviderFactory> (() => monoFactory);
			DependencyInjector.RegisterCollection<IConnectionProviderFactoryExtension> (monoFactory);
			DependencyInjector.RegisterDefaults<IDefaultConnectionSettings> (2, () => this);
		}

		public bool InstallDefaultCertificateValidator {
			get { return false; }
		}

		public ISslStreamProvider DefaultSslStreamProvider {
			get { return null; }
		}

		public SecurityProtocolType? SecurityProtocol {
			get { return (SecurityProtocolType)0xfc0; }
		}

		public Guid? InstallTlsProvider {
			get { return MonoConnectionProviderFactory.NewTlsID; }
		}
	}
}

