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
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.HttpClient;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoHttpProvider : IHttpProvider
	{
		readonly HttpProviderType type;
		readonly MonoTlsProvider legacyTlsProvider;
		readonly MonoTlsProvider newTlsProvider;
		readonly SslStreamProviderImpl legacyStreamProvider;
		readonly SslStreamProviderImpl newStreamProvider;

		internal MonoHttpProvider (HttpProviderType type)
		{
			this.type = type;

			newTlsProvider = DependencyInjector.Get<NewTlsProvider> ();
			legacyTlsProvider = MonoTlsProviderFactory.GetDefaultProvider ();
			legacyStreamProvider = new SslStreamProviderImpl (legacyTlsProvider);
			newStreamProvider = new SslStreamProviderImpl (newTlsProvider);
		}

		public bool SupportsWebRequest {
			get { return true; }
		}

		public IHttpWebRequest CreateWebRequest (Uri uri)
		{
			HttpWebRequest request;
			switch (type) {
			case HttpProviderType.MonoWithOldTLS:
				request = MonoTlsProviderFactory.CreateHttpsRequest (uri, legacyTlsProvider);
				break;
			case HttpProviderType.MonoWithNewTLS:
				request = MonoTlsProviderFactory.CreateHttpsRequest (uri, newTlsProvider);
				break;
			default:
				throw new InvalidOperationException ();
			}
			return CreateWebRequest (request);
		}

		public IHttpWebRequest CreateWebRequest (HttpWebRequest request)
		{
			return new HttpWebRequestImpl (request);
		}

		public HttpServer CreateServer (IPortableEndPoint endpoint, ListenerFlags flags, IServerCertificate serverCertificate)
		{
			ISslStreamProvider streamProvider;
			switch (type) {
			case HttpProviderType.MonoWithOldTLS:
				streamProvider = legacyStreamProvider;
				break;
			case HttpProviderType.MonoWithNewTLS:
				streamProvider = newStreamProvider;
				break;
			default:
				throw new InvalidOperationException ();
			}

			return new HttpServer (this, endpoint, flags, serverCertificate);
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
				var serverCertificate = CertificateProvider.GetCertificate (certificate);
				return CreateServerStream (stream, serverCertificate);
			}

			public Stream CreateServerStream (Stream stream, X509Certificate serverCertificate)
			{
				var sslStream = provider.CreateSslStream (stream, false, null, null);
				sslStream.AuthenticateAsServer (serverCertificate);
				return sslStream.AuthenticatedStream;
			}
		}

		public bool SupportsHttpClient {
			get { return false; }
		}

		public IHttpClientHandler CreateHttpClient ()
		{
			throw new InvalidOperationException ();
		}

		public ISslStreamProvider SslStreamProvider {
			get {
				switch (type) {
				case HttpProviderType.MonoWithOldTLS:
					return legacyStreamProvider;
				case HttpProviderType.MonoWithNewTLS:
					return newStreamProvider;
				default:
					throw new InvalidOperationException ();
				}
			}
		}
	}
}

