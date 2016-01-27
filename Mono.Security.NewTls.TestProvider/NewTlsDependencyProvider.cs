//
// DependencyProvider.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Net;
using System.Threading;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.MonoConnectionFramework;
using Xamarin.WebTests.MonoTestFramework;
using Xamarin.WebTests.Server;

using Mono.Security.Interface;
using Mono.Security.Providers.NewTls;
using Mono.Security.Providers.DotNet;
using Mono.Security.Providers.OldTls;

[assembly: DependencyProvider (typeof (Mono.Security.NewTls.TestProvider.NewTlsDependencyProvider))]

namespace Mono.Security.NewTls.TestProvider
{
	using ConnectionFramework;
	using TestFramework;

	public sealed class NewTlsDependencyProvider : IDependencyProvider, IExtensionProvider<MonoTlsProvider>
	{
		const ConnectionProviderFlags DefaultFlags = ConnectionProviderFlags.SupportsSslStream | ConnectionProviderFlags.SupportsHttp;
		const ConnectionProviderFlags NewTlsFlags = DefaultFlags | ConnectionProviderFlags.SupportsTls12 |
			ConnectionProviderFlags.SupportsAeadCiphers | // ConnectionProviderFlags.SupportsEcDheCiphers |
			ConnectionProviderFlags.SupportsClientCertificates;

		public void Initialize ()
		{
			DependencyInjector.RegisterAssembly (typeof(MonoTestFrameworkDependencyProvider).Assembly);

			DependencyInjector.RegisterDependency<ICryptoProvider> (() => new CryptoProvider ());
			DependencyInjector.RegisterExtension<MonoTlsProvider> (this);

			var factory = DependencyInjector.Get<MonoConnectionProviderFactory> ();

			var newTlsProvider = new NewTlsProvider ();
			factory.RegisterProvider ("NewTLS", newTlsProvider, ConnectionProviderType.NewTLS, NewTlsFlags);

			var oldTlsProvider = new OldTlsProvider ();
			factory.RegisterProvider ("OldTLS", oldTlsProvider, ConnectionProviderType.OldTLS, DefaultFlags);
		}

		public IMonoTlsProviderExtensions GetExtensionObject (MonoTlsProvider provider)
		{
			if (provider.ID == MonoConnectionProviderFactory.NewTlsID)
				return new MonoTlsProviderExtensions (provider);
			return null;
		}

		IExtensionObject<MonoTlsProvider> IExtensionProvider<MonoTlsProvider>.GetExtensionObject (MonoTlsProvider provider)
		{
			return GetExtensionObject (provider);
		}
	}
}

