//
// MonoSslStreamProvider.cs
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
using System.Threading;
using System.Threading.Tasks;

using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoSslStreamProvider : ISslStreamProvider
	{
		readonly MSI.MonoTlsProvider tlsProvider;

		internal MonoSslStreamProvider (MSI.MonoTlsProvider tlsProvider)
		{
			this.tlsProvider = tlsProvider;
		}

		static SslProtocols GetSslProtocol ()
		{
			return (SslProtocols)ServicePointManager.SecurityProtocol;
		}

		static RemoteCertificateValidationCallback GetValidationCallback (ServerParameters parameters)
		{
			var validator = parameters.ServerCertificateValidator;
			if (validator == null)
				return null;

			return ((CertificateValidator)validator).ValidationCallback;
		}

		static RemoteCertificateValidationCallback GetValidationCallback (ClientParameters parameters)
		{
			var validator = parameters.ClientCertificateValidator;
			if (validator == null)
				return null;

			return ((CertificateValidator)validator).ValidationCallback;
		}

		static MSI.ICertificateValidator GetCertificateValidator (ICertificateValidator validator)
		{
			if (validator == null)
				return null;

			var settings = new MSI.MonoTlsSettings ();
			settings.ServerCertificateValidationCallback = (s, c, ch, e) => {
				return ((CertificateValidator)validator).ValidationCallback (s, c, ch, (SslPolicyErrors)e);
			};
			return MSI.CertificateValidationHelper.CreateDefaultValidator (settings);
		}

		static X509Certificate2Collection GetClientCertificates (ClientParameters parameters)
		{
			if (parameters.ClientCertificate == null)
				return null;

			var clientCertificateCollection = new X509Certificate2Collection ();
			var certificate = (X509Certificate2)CertificateProvider.GetCertificate (parameters.ClientCertificate);
			clientCertificateCollection.Add (certificate);

			return clientCertificateCollection;
		}

		public ISslStream CreateServerStream (Stream stream, ServerParameters parameters)
		{
			var certificate = CertificateProvider.GetCertificate (parameters.ServerCertificate);

			var protocol = GetSslProtocol ();
			var validator = GetCertificateValidator (parameters.ServerCertificateValidator);

			var askForCert = (parameters.Flags & (ServerFlags.AskForClientCertificate|ServerFlags.RequireClientCertificate)) != 0;

			var sslStream = tlsProvider.CreateSslStream (stream, false, validator);
			sslStream.AuthenticateAsServer (certificate, askForCert, protocol, false);

			return new MonoSslStreamWrapper (sslStream);
		}

		public async Task<ISslStream> CreateServerStreamAsync (Stream stream, ServerParameters parameters, CancellationToken cancellationToken)
		{
			var certificate = CertificateProvider.GetCertificate (parameters.ServerCertificate);

			var protocol = GetSslProtocol ();
			var validator = GetCertificateValidator (parameters.ServerCertificateValidator);

			var askForCert = (parameters.Flags & (ServerFlags.AskForClientCertificate|ServerFlags.RequireClientCertificate)) != 0;

			var sslStream = tlsProvider.CreateSslStream (stream, false, validator);
			await sslStream.AuthenticateAsServerAsync (certificate, askForCert, protocol, false).ConfigureAwait (false);

			return new MonoSslStreamWrapper (sslStream);
		}

		public async Task<ISslStream> CreateClientStreamAsync (Stream stream, string targetHost, ClientParameters parameters, CancellationToken cancellationToken)
		{
			var protocol = GetSslProtocol ();
			var validator = GetCertificateValidator (parameters.ClientCertificateValidator);

			var clientCertificates = GetClientCertificates (parameters);

			var sslStream = tlsProvider.CreateSslStream (stream, false, validator, null);
			await sslStream.AuthenticateAsClientAsync (targetHost, clientCertificates, protocol, false).ConfigureAwait (false);

			return new MonoSslStreamWrapper (sslStream);
		}

		class MonoSslStreamWrapper : ISslStream
		{
			readonly MSI.MonoSslStream stream;

			public MonoSslStreamWrapper (MSI.MonoSslStream stream)
			{
				this.stream = stream;
			}

			public bool HasClientCertificate {
				get { return stream.IsAuthenticated && stream.IsMutuallyAuthenticated; }
			}

			public Stream AuthenticatedStream {
				get { return stream.AuthenticatedStream; }
			}
		}
	}
}

