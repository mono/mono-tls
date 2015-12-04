using System;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Providers;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	public interface IMonoTlsProviderFactory : IExtensionCollection
	{
		MonoTlsProvider Provider {
			get;
		}

		ConnectionProviderType ConnectionProviderType {
			get;
		}

		ConnectionProviderFlags ConnectionProviderFlags {
			get;
		}
	}
}

