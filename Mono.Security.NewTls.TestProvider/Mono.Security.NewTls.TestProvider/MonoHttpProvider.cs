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
		readonly HttpProviderType type;
		readonly MSI.MonoTlsProvider legacyTlsProvider;
		readonly MSI.MonoTlsProvider newTlsProvider;
		// readonly SslStreamProviderImpl legacyStreamProvider;
		// readonly SslStreamProviderImpl newStreamProvider;

		internal MonoHttpProvider (HttpProviderType type)
		{
			this.type = type;

			newTlsProvider = DependencyInjector.Get<NewTlsProvider> ();
			legacyTlsProvider = MSI.MonoTlsProviderFactory.GetDefaultProvider ();
			// legacyStreamProvider = new SslStreamProviderImpl (legacyTlsProvider);
			// newStreamProvider = new SslStreamProviderImpl (newTlsProvider);
		}

		public bool SupportsWebRequest {
			get { return true; }
		}

		public IHttpWebRequest CreateWebRequest (Uri uri)
		{
			HttpWebRequest request;
			switch (type) {
			case HttpProviderType.MonoWithOldTLS:
				request = MSI.MonoTlsProviderFactory.CreateHttpsRequest (uri, legacyTlsProvider);
				break;
			case HttpProviderType.MonoWithNewTLS:
				request = MSI.MonoTlsProviderFactory.CreateHttpsRequest (uri, newTlsProvider);
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

		public HttpServer CreateServer (IPortableEndPoint endpoint, ListenerFlags flags, ServerParameters parameters = null)
		{
			return new HttpServer (this, endpoint, flags, parameters);
		}

		#if FIXME
		class SslStreamProviderImpl : ISslStreamProvider
		{
			readonly MSI.MonoTlsProvider provider;

			public SslStreamProviderImpl (MSI.MonoTlsProvider provider)
			{
				this.provider = provider;
			}

			ISslStream ISslStreamProvider.CreateServerStream (Stream stream, ServerParameters parameters)
			{
				var serverCertificate = CertificateProvider.GetCertificate (certificate);

				MSI.ICertificateValidator msiValidator = null;
				if (validator != null) {
					var settings = new MSI.MonoTlsSettings ();
					settings.ServerCertificateValidationCallback = (s, c, ch, e) => {
						return ((CertificateValidator)validator).ValidationCallback (s, c, ch, (SslPolicyErrors)e);
					};
					msiValidator = MSI.CertificateValidationHelper.CreateDefaultValidator (settings);
				}

				return CreateServerStream (stream, serverCertificate, msiValidator, flags);
			}

			public Stream CreateServerStream (Stream stream, X509Certificate serverCertificate, MSI.ICertificateValidator validator, ListenerFlags flags)
			{
				var protocols = (SslProtocols)ServicePointManager.SecurityProtocol;
				var clientCertificateRequired = (flags & ListenerFlags.RequireClientCertificate) != 0;

				var sslStream = provider.CreateSslStream (stream, false, validator, null);
				sslStream.AuthenticateAsServer (serverCertificate, clientCertificateRequired, protocols, false);
				return sslStream.AuthenticatedStream;
			}
		}
		#endif

		public bool SupportsHttpClient {
			get { return false; }
		}

		public IHttpClientHandler CreateHttpClient ()
		{
			throw new InvalidOperationException ();
		}

		public ISslStreamProvider SslStreamProvider {
			get {
				throw new NotImplementedException ();
				#if FIXME
				switch (type) {
				case HttpProviderType.MonoWithOldTLS:
					return legacyStreamProvider;
				case HttpProviderType.MonoWithNewTLS:
					return newStreamProvider;
				default:
					throw new InvalidOperationException ();
				}
				#endif
			}
		}

		public ISslStreamProvider DefaultSslStreamProvider {
			get {
				#if FIXME
				return newStreamProvider;
				#else
				throw new NotImplementedException();
				#endif
			}
		}
	}
}

