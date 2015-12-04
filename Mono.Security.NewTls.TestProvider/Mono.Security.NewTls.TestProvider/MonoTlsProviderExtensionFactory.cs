using System;
using Xamarin.AsyncTests;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoTlsProviderExtensionFactory : IExtensionProvider<MonoTlsProvider>
	{
		public MonoProviderExtensions GetExtensionObject (MonoTlsProvider provider)
		{
			if (provider.ID == MonoConnectionProviderFactory.NewTlsID)
				return new MonoProviderExtensions (provider);
			return null;
		}
		
		IExtensionObject<MonoTlsProvider> IExtensionProvider<MonoTlsProvider>.GetExtensionObject (MonoTlsProvider instance)
		{
			return GetExtensionObject (instance);
		}
	}
}

