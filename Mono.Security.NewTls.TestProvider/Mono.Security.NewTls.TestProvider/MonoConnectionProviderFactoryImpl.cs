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
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Server;

using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoConnectionProviderFactoryImpl : MonoConnectionProviderFactory
	{
		readonly MSI.MonoTlsProvider newTlsProvider;
		readonly MSI.MonoTlsProvider legacyTlsProvider;
		readonly DefaultHttpProvider dotNetHttpProvider;
		readonly DotNetSslStreamProvider dotNetStreamProvider;
		readonly DotNetConnectionProvider dotNetConnectionProvider;
		readonly MonoConnectionProviderImpl newTlsConnectionProvider;
		readonly MonoConnectionProviderImpl legacyConnectionProvider;
		readonly MonoConnectionProviderImpl monoWithNewTlsConnectionProvider;
		readonly MonoConnectionProviderImpl monoWithOldTlsConnectionProvider;
		readonly OpenSslConnectionProvider openSslConnectionProvider;
		readonly MonoConnectionProviderImpl platformDefaultConnectionProvider;
		readonly ManualConnectionProvider manualConnectionProvider;

		internal MonoConnectionProviderFactoryImpl ()
		{
			dotNetStreamProvider = new DotNetSslStreamProvider ();
			dotNetHttpProvider = new DefaultHttpProvider (dotNetStreamProvider);
			dotNetConnectionProvider = new DotNetConnectionProvider (this, ConnectionProviderType.DotNet, dotNetStreamProvider, dotNetHttpProvider);
			Install (dotNetConnectionProvider);

			newTlsProvider = DependencyInjector.Get<NewTlsProvider> ();
			newTlsConnectionProvider = new MonoConnectionProviderImpl (this, ConnectionProviderType.NewTLS, newTlsProvider, false);
			Install (newTlsConnectionProvider);

			legacyTlsProvider = MSI.MonoTlsProviderFactory.GetDefaultProvider ();
			legacyConnectionProvider = new MonoConnectionProviderImpl (this, ConnectionProviderType.OldTLS, legacyTlsProvider, false);
			Install (legacyConnectionProvider);

			monoWithNewTlsConnectionProvider = new MonoConnectionProviderImpl (this, ConnectionProviderType.MonoWithNewTLS, newTlsProvider, true);
			Install (monoWithNewTlsConnectionProvider);

			monoWithOldTlsConnectionProvider = new MonoConnectionProviderImpl (this, ConnectionProviderType.MonoWithOldTLS, legacyTlsProvider, true);
			Install (monoWithOldTlsConnectionProvider);

			platformDefaultConnectionProvider = new MonoConnectionProviderImpl (this, ConnectionProviderType.PlatformDefault, newTlsProvider, true);
			Install (platformDefaultConnectionProvider);

			openSslConnectionProvider = new OpenSslConnectionProvider (this);
			Install (openSslConnectionProvider);

			manualConnectionProvider = new ManualConnectionProvider (this, ConnectionProviderFlags.None);
			Install (manualConnectionProvider);
		}

		public override IHttpProvider DefaultHttpProvider {
			get { return newTlsConnectionProvider.HttpProvider; }
		}

		public override ISslStreamProvider DefaultSslStreamProvider {
			get { return newTlsConnectionProvider; }
		}
	}
}

