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
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;
using Mono.Security.Providers.NewTls;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Framework;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoHttpsProvider : IHttpsProvider
	{
		readonly MonoTlsProvider legacyTlsProvider;
		readonly MonoTlsProvider newTlsProvider;

		internal MonoHttpsProvider ()
		{
			newTlsProvider = DependencyInjector.Get<NewTlsProvider> ();
			legacyTlsProvider = MonoTlsProviderFactory.GetDefaultProvider ();
		}

		public HttpWebRequest CreateRequest (HttpsProviderType type, Uri requestUri)
		{
			switch (type) {
			case HttpsProviderType.MonoWithOldTLS:
				return MonoTlsProviderFactory.CreateHttpsRequest (requestUri, legacyTlsProvider);
			case HttpsProviderType.MonoWithNewTLS:
				return MonoTlsProviderFactory.CreateHttpsRequest (requestUri, newTlsProvider);
			default:
				throw new InvalidOperationException ();
			}
		}

		public HttpServer CreateServer (IPortableEndPoint endpoint, IServerCertificate certificate)
		{
			var cert = new X509Certificate2 (certificate.Data, certificate.Password);
			var wrapper = new ServerCertificate { InstallDefaultValidationCallback = false, Certificate = cert };
			return new HttpServer (endpoint, false, wrapper);
		}
	}
}

