﻿//
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
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Server;

using MSI = Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

namespace Mono.Security.NewTls.TestProvider
{
	class MonoConnectionProvider : ConnectionProvider, ISslStreamProvider
	{
		readonly MSI.MonoTlsProvider tlsProvider;
		readonly MonoHttpProvider httpProvider;
		readonly bool enableMonoExtensions;

		public MonoConnectionProvider (MonoConnectionProviderFactory factory, MSI.MonoTlsProvider tlsProvider, bool enableMonoExtensions)
			: base (factory)
		{
			this.tlsProvider = tlsProvider;
			this.enableMonoExtensions = enableMonoExtensions;
			this.httpProvider = new MonoHttpProvider (this);
		}

		public bool EnableMonoExtensions {
			get { return enableMonoExtensions; }
		}

		public override IClient CreateClient (ClientParameters parameters)
		{
			if (EnableMonoExtensions)
				return new MonoClient (parameters, this);
			else
				return new DotNetClient (parameters, this);
		}

		public override IServer CreateServer (ServerParameters parameters)
		{
			if (EnableMonoExtensions)
				return new MonoServer (parameters, this);
			else
				return new DotNetServer (parameters, this);
		}

		public bool IsNewTls {
			get { return tlsProvider is NewTlsProvider; }
		}

		public override bool SupportsSslStreams {
			get { return true; }
		}

		protected override ISslStreamProvider GetSslStreamProvider ()
		{
			return this;
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

		ISslStream ISslStreamProvider.CreateServerStream (Stream stream, ServerParameters parameters)
		{
			return CreateServerStream (stream, parameters);
		}

		public MonoSslStream CreateServerStream (Stream stream, ServerParameters parameters)
		{
			var certificate = CertificateProvider.GetCertificate (parameters.ServerCertificate);

			var protocol = CallbackHelpers.GetSslProtocol ();
			var validator = CallbackHelpers.GetCertificateValidator (parameters.ServerCertificateValidator);

			var askForCert = (parameters.Flags & (ServerFlags.AskForClientCertificate|ServerFlags.RequireClientCertificate)) != 0;

			var sslStream = tlsProvider.CreateSslStream (stream, false, validator);
			sslStream.AuthenticateAsServer (certificate, askForCert, protocol, false);

			return new MonoSslStream (sslStream);
		}

		async Task<ISslStream> ISslStreamProvider.CreateServerStreamAsync (Stream stream, ServerParameters parameters, CancellationToken cancellationToken)
		{
			return await CreateServerStreamAsync (stream, parameters, cancellationToken).ConfigureAwait (false);
		}

		public Task<MonoSslStream> CreateServerStreamAsync (Stream stream, ServerParameters parameters, CancellationToken cancellationToken)
		{
			return CreateServerStreamAsync (stream, parameters, null, cancellationToken);
		}

		public async Task<MonoSslStream> CreateServerStreamAsync (Stream stream, ServerParameters parameters, MSI.MonoTlsSettings settings, CancellationToken cancellationToken)
		{
			var certificate = CertificateProvider.GetCertificate (parameters.ServerCertificate);

			var protocol = CallbackHelpers.GetSslProtocol ();

			MSI.ICertificateValidator validator = null;
			if (settings != null)
				CallbackHelpers.AddCertificateValidator (settings, parameters.ServerCertificateValidator);
			else
				validator = CallbackHelpers.GetCertificateValidator (parameters.ServerCertificateValidator);

			var askForCert = (parameters.Flags & (ServerFlags.AskForClientCertificate|ServerFlags.RequireClientCertificate)) != 0;

			var sslStream = tlsProvider.CreateSslStream (stream, false, validator, settings);
			var monoSslStream = new MonoSslStream (sslStream);

			try {
				await sslStream.AuthenticateAsServerAsync (certificate, askForCert, protocol, false).ConfigureAwait (false);
			} catch (Exception ex) {
				var lastError = monoSslStream.LastError;
				if (lastError != null)
					throw new AggregateException (ex, lastError);
				throw;
			}

			return monoSslStream;
		}

		async Task<ISslStream> ISslStreamProvider.CreateClientStreamAsync (Stream stream, string targetHost, ClientParameters parameters, CancellationToken cancellationToken)
		{
			return await CreateClientStreamAsync (stream, targetHost, parameters, cancellationToken).ConfigureAwait (false);
		}

		public Task<MonoSslStream> CreateClientStreamAsync (Stream stream, string targetHost, ClientParameters parameters, CancellationToken cancellationToken)
		{
			return CreateClientStreamAsync (stream, targetHost, parameters, null, cancellationToken);
		}

		public async Task<MonoSslStream> CreateClientStreamAsync (Stream stream, string targetHost, ClientParameters parameters, MSI.MonoTlsSettings settings, CancellationToken cancellationToken)
		{
			var protocol = CallbackHelpers.GetSslProtocol ();

			MSI.ICertificateValidator validator = null;
			if (settings != null)
				CallbackHelpers.AddCertificateValidator (settings, parameters.ClientCertificateValidator);
			else
				validator = CallbackHelpers.GetCertificateValidator (parameters.ClientCertificateValidator);

			var clientCertificates = CallbackHelpers.GetClientCertificates (parameters);

			var sslStream = tlsProvider.CreateSslStream (stream, false, validator, settings);
			var monoSslStream = new MonoSslStream (sslStream);

			try {
				await sslStream.AuthenticateAsClientAsync (targetHost, clientCertificates, protocol, false).ConfigureAwait (false);
			} catch (Exception ex) {
				var lastError = monoSslStream.LastError;
				if (lastError != null)
					throw new AggregateException (ex, lastError);
				throw;
			}

			return monoSslStream;
		}
	}
}

