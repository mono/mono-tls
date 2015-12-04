//
// MonoConnectionProviderFactory.cs
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
using System.Net.Security;
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Server;

using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;
using Mono.Security.Providers.OldTls;

namespace Mono.Security.NewTls.TestProvider
{
	using MonoConnectionFramework;
	using TestFramework;

	class OldMonoConnectionProviderFactory : IConnectionProviderFactoryExtension
	{
		MSI.MonoTlsProvider newTlsProvider;
		MSI.MonoTlsProvider oldTlsProvider;
		MonoConnectionProvider newTlsConnectionProvider;
		MonoConnectionProvider oldTlsConnectionProvider;
		MonoConnectionProvider monoWithNewTlsConnectionProvider;

		const ConnectionProviderFlags DefaultFlags = ConnectionProviderFlags.SupportsSslStream | ConnectionProviderFlags.SupportsHttp;
		const ConnectionProviderFlags NewTlsFlags = DefaultFlags | ConnectionProviderFlags.SupportsTls12 | ConnectionProviderFlags.SupportsAeadCiphers | ConnectionProviderFlags.SupportsEcDheCiphers;

		public void Initialize (ConnectionProviderFactory factory)
		{
			newTlsProvider = new NewTlsProvider ();
			MSI.MonoTlsProviderFactory.InstallProvider (newTlsProvider);

			newTlsConnectionProvider = new MonoConnectionProvider (factory, ConnectionProviderType.NewTLS, NewTlsFlags, newTlsProvider);
			factory.Install (newTlsConnectionProvider);

			oldTlsProvider = new OldTlsProvider ();
			oldTlsConnectionProvider = new MonoConnectionProvider (factory, ConnectionProviderType.MonoWithOldTLS, DefaultFlags, oldTlsProvider);
			factory.Install (oldTlsConnectionProvider);

			monoWithNewTlsConnectionProvider = new MonoConnectionProvider (factory, ConnectionProviderType.MonoWithNewTLS, NewTlsFlags, newTlsProvider);
			factory.Install (monoWithNewTlsConnectionProvider);
		}
	}
}

