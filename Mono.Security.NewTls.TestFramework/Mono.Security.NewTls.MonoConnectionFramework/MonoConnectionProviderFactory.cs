using System;
using System.Net;
using System.Threading;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Providers;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public class MonoConnectionProviderFactory : IConnectionProviderFactoryExtension, ISingletonInstance
	{
		int initialized;

		public static readonly Guid NewTlsID = new Guid ("e5ff34f1-8b7a-4aa6-aff9-24719d709693");
		public static readonly Guid OldTlsID = new Guid ("cf8baa0d-c6ed-40ae-b512-dec8d097e9af");

		internal MonoConnectionProviderFactory ()
		{
		}

		public void Initialize (ConnectionProviderFactory factory, IDefaultConnectionSettings settings)
		{
			if (Interlocked.Exchange (ref initialized, 1) != 0)
				throw new InvalidOperationException ();

			var providers = DependencyInjector.GetCollection<IMonoTlsProviderFactory> ();
			foreach (var provider in providers) {
				var monoProvider = new MonoConnectionProvider (factory, provider.ConnectionProviderType, provider.ConnectionProviderFlags, provider.Provider);
				factory.Install (monoProvider);
			}
		}

		public void RegisterProvider (IMonoTlsProviderFactory factory)
		{
			if (initialized != 0)
				throw new InvalidOperationException ();

			DependencyInjector.RegisterCollection<IMonoTlsProviderFactory> (factory);
		}

		public void RegisterProvider (MonoTlsProvider provider, ConnectionProviderType type, ConnectionProviderFlags flags)
		{
			RegisterProvider (new FactoryImpl (provider, type, flags));
		}

		class FactoryImpl : IMonoTlsProviderFactory
		{
			public MonoTlsProvider Provider {
				get;
				private set;
			}

			public ConnectionProviderType ConnectionProviderType {
				get;
				private set;
			}

			public ConnectionProviderFlags ConnectionProviderFlags {
				get;
				private set;
			}

			public FactoryImpl (MonoTlsProvider provider, ConnectionProviderType type, ConnectionProviderFlags flags)
			{
				Provider = provider;
				ConnectionProviderType = type;
				ConnectionProviderFlags = flags;
			}
		}
	}
}

