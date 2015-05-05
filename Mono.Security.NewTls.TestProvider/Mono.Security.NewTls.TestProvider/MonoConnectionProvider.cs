//
// MonoConnectionProvider.cs
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
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Server;

using MSI = Mono.Security.Interface;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoConnectionProvider : ConnectionProvider
	{
		readonly MSI.MonoTlsProvider tlsProvider;
		readonly ISslStreamProvider sslStreamProvider;
		readonly MonoHttpProvider httpProvider;

		public MonoConnectionProvider (MonoConnectionProviderFactory factory, MonoSslStreamProvider sslStreamProvider)
			: base (factory)
		{
			this.sslStreamProvider = sslStreamProvider;
			this.tlsProvider = sslStreamProvider.MonoTlsProvider;
			this.httpProvider = new MonoHttpProvider (this);
		}

		public override IClient CreateClient (ClientParameters parameters)
		{
			return new DotNetClient (GetEndPoint (parameters), SslStreamProvider, parameters);
		}

		public override IServer CreateServer (ServerParameters parameters)
		{
			return new DotNetServer (GetEndPoint (parameters), SslStreamProvider, parameters);
		}

		public override bool SupportsSslStreams {
			get { return true; }
		}

		protected override ISslStreamProvider GetSslStreamProvider ()
		{
			return sslStreamProvider;
		}

		internal MSI.MonoTlsProvider MonoTlsProvider {
			get { return tlsProvider; }
		}

		public override bool SupportsHttp {
			get { return true; }
		}

		protected override IHttpProvider GetHttpProvider ()
		{
			return httpProvider;
		}

		static IPEndPoint GetEndPoint (ConnectionParameters parameters)
		{
			if (parameters.EndPoint != null)
				return new IPEndPoint (IPAddress.Parse (parameters.EndPoint.Address), parameters.EndPoint.Port);
			else
				return new IPEndPoint (IPAddress.Loopback, 4433);
		}
	}
}

