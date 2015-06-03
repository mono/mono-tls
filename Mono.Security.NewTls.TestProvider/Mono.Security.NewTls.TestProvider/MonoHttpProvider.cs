//
// MonoHttpProvider.cs
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
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.HttpFramework;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.HttpClient;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoHttpProvider : IHttpProvider
	{
		readonly MonoConnectionProviderImpl connectionProvider;

		internal MonoHttpProvider (MonoConnectionProviderImpl connectionProvider)
		{
			this.connectionProvider = connectionProvider;
		}

		public bool SupportsWebRequest {
			get { return true; }
		}

		public IHttpWebRequest CreateWebRequest (Uri uri)
		{
			var settings = new TlsSettings {
				UseServicePointManagerCallback = true, SkipSystemValidators = true, CallbackNeedsCertificateChain = false
			};
			var request = MSI.MonoTlsProviderFactory.CreateHttpsRequest (uri, connectionProvider.MonoTlsProvider, settings);
			return CreateWebRequest (request);
		}

		public IHttpWebRequest CreateWebRequest (HttpWebRequest request)
		{
			return new HttpWebRequestImpl (request);
		}

		public HttpServer CreateServer (IPortableEndPoint endpoint, ListenerFlags flags, ServerParameters parameters = null)
		{
			return new HttpServer (this, endpoint, flags, parameters);
		}

		public bool SupportsHttpClient {
			get { return false; }
		}

		public IHttpClientHandler CreateHttpClient ()
		{
			throw new InvalidOperationException ();
		}

		public ISslStreamProvider SslStreamProvider {
			get { return connectionProvider.SslStreamProvider; }
		}
	}
}
