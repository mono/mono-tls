//
// MonoHttpsConnectionProvider.cs
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
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;
using Mono.Security.Providers.NewTls;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Framework;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoHttpsProvider : IHttpsProvider
	{
		readonly MonoTlsProvider legacyTlsProvider;
		readonly MonoTlsProvider newTlsProvider;
		readonly SslStreamProviderImpl legacyStreamProvider;
		readonly SslStreamProviderImpl newStreamProvider;
		readonly IHttpWebRequestProvider requestProvider;

		internal MonoHttpsProvider ()
		{
			newTlsProvider = DependencyInjector.Get<NewTlsProvider> ();
			legacyTlsProvider = MonoTlsProviderFactory.GetDefaultProvider ();
			legacyStreamProvider = new SslStreamProviderImpl (legacyTlsProvider);
			newStreamProvider = new SslStreamProviderImpl (newTlsProvider);
			requestProvider = DependencyInjector.Get<IHttpWebRequestProvider> ();
		}

		public IHttpWebRequest CreateRequest (HttpsProviderType type, Uri requestUri)
		{
			HttpWebRequest request;
			switch (type) {
			case HttpsProviderType.MonoWithOldTLS:
				request = MonoTlsProviderFactory.CreateHttpsRequest (requestUri, legacyTlsProvider);
				break;
			case HttpsProviderType.MonoWithNewTLS:
				request = MonoTlsProviderFactory.CreateHttpsRequest (requestUri, newTlsProvider);
				break;
			default:
				throw new InvalidOperationException ();
			}
			return requestProvider.Create (request);
		}

		public IHttpServer CreateServer (HttpsProviderType type, IPortableEndPoint endpoint, IServerCertificate certificate)
		{
			ISslStreamProvider streamProvider;
			switch (type) {
			case HttpsProviderType.MonoWithOldTLS:
				streamProvider = legacyStreamProvider;
				break;
			case HttpsProviderType.MonoWithNewTLS:
				streamProvider = newStreamProvider;
				break;
			default:
				throw new InvalidOperationException ();
			}
			return new HttpServer (endpoint, false, certificate, streamProvider);
		}

		static ServerCertificate GetCertificate (IServerCertificate certificate)
		{
			var cert = new X509Certificate2 (certificate.Data, certificate.Password);
			return new ServerCertificate { Certificate = cert };
		}

		class SslStreamProviderImpl : ISslStreamProvider
		{
			readonly MonoTlsProvider provider;

			public SslStreamProviderImpl (MonoTlsProvider provider)
			{
				this.provider = provider;
			}

			Stream ISslStreamProvider.CreateServerStream (Stream stream, IServerCertificate certificate)
			{
				var serverCertificate = GetCertificate (certificate);
				return CreateServerStream (stream, serverCertificate);
			}

			public Stream CreateServerStream (Stream stream, ServerCertificate serverCertificate)
			{
				var sslStream = provider.CreateSslStream (stream, false, null, null, null);
				sslStream.AuthenticateAsServer (serverCertificate.Certificate);
				return sslStream.AuthenticatedStream;
			}
		}
	}
}

