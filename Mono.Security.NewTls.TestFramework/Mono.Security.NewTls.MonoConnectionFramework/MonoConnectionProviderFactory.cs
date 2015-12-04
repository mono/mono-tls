using System;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public class MonoConnectionProviderFactory : IConnectionProviderFactoryExtension
	{
		public static readonly Guid NewTlsID = new Guid ("e5ff34f1-8b7a-4aa6-aff9-24719d709693");
		public static readonly Guid OldTlsID = new Guid ("cf8baa0d-c6ed-40ae-b512-dec8d097e9af");

		public void Initialize (ConnectionProviderFactory factory)
		{
			var providers = DependencyInjector.GetCollection<IMonoTlsProviderFactory> ();
			foreach (var provider in providers) {
				var monoProvider = new MonoConnectionProvider (factory, provider.ConnectionProviderType, provider.ConnectionProviderFlags, provider.Provider);
				factory.Install (monoProvider);
			}
		}
	}
}

