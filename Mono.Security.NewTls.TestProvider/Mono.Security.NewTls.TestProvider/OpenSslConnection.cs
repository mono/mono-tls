﻿//
// OpenSslConnection.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2014 Xamarin Inc. (http://www.xamarin.com)
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
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Server;
using System.Net.Security;

namespace Mono.Security.NewTls.TestProvider
{
	public abstract class OpenSslConnection : Connection, ICommonConnection
	{
		public override bool SupportsCleanShutdown {
			get { return true; }
		}

		public OpenSslConnection (OpenSslConnectionProvider provider, ConnectionParameters parameters)
			: base (GetEndPoint (parameters), parameters)
		{
			this.provider = provider;
			createTcs = new TaskCompletionSource<object> ();
		}

		protected NativeOpenSsl openssl;
		OpenSslConnectionProvider provider;
		TlsConnectionInfo connectionInfo;
		TaskCompletionSource<object> createTcs;

		public override ProtocolVersions SupportedProtocols {
			get { return provider.SupportedProtocols; }
		}

		public Stream Stream {
			get { return openssl; }
		}

		public ISslStream SslStream {
			get { throw new NotImplementedException (); }
		}

		public bool SupportsConnectionInfo {
			get { return true; }
		}

		protected abstract bool IsServer {
			get;
		}

		public ProtocolVersions ProtocolVersion {
			get {
				switch (openssl.Protocol) {
				case NativeOpenSslProtocol.TLS10:
					return ProtocolVersions.Tls10;
				case NativeOpenSslProtocol.TLS11:
					return ProtocolVersions.Tls11;
				case NativeOpenSslProtocol.TLS12:
					return ProtocolVersions.Tls12;
				default:
					throw new InvalidOperationException ();
				}
			}
		}

		public TlsConnectionInfo GetConnectionInfo ()
		{
			if (connectionInfo != null)
				return connectionInfo;

			connectionInfo = new TlsConnectionInfo {
				CipherCode = (CipherSuiteCode)openssl.CurrentCipher
			};

			return connectionInfo;
		}

		static IPortableEndPoint GetEndPoint (ConnectionParameters parameters)
		{
			if (parameters.EndPoint != null)
				return parameters.EndPoint;

			var support = DependencyInjector.Get<IPortableEndPointSupport> ();
			return support.GetLoopbackEndpoint (4433);
		}

		protected IPEndPoint GetEndPoint ()
		{
			if (EndPoint != null)
				return new IPEndPoint (IPAddress.Parse (EndPoint.Address), EndPoint.Port);
			else
				return new IPEndPoint (IPAddress.Loopback, 4433);
		}

		NativeOpenSslProtocol GetProtocolVersion ()
		{
			var version = Parameters.ProtocolVersion;
			if (version == ProtocolVersions.Unspecified)
				return NativeOpenSslProtocol.TLS12;
			if ((version & ProtocolVersions.Tls12) != 0)
				return NativeOpenSslProtocol.TLS12;
			if ((version & ProtocolVersions.Tls11) != 0)
				return NativeOpenSslProtocol.TLS11;
			if ((version & ProtocolVersions.Tls10) != 0)
				return NativeOpenSslProtocol.TLS10;
			throw new InvalidOperationException ();
		}

		NativeOpenSsl.RemoteValidationCallback GetValidationCallback ()
		{
			var clientParams = Parameters as ClientParameters;
			if (clientParams == null)
				return null;
			var validator = (CertificateValidator)clientParams.ClientCertificateValidator;
			if (validator == null)
				return null;

			return (ok, cert) => {
				var errors = SslPolicyErrors.None;
				if (!ok)
					errors |= SslPolicyErrors.RemoteCertificateChainErrors;
				return validator.ValidationCallback (this, cert, null, errors);
			};
		}

		public sealed override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			var protocol = GetProtocolVersion ();
			ctx.LogMessage ("Starting {0} version {1}.", this, protocol);
			openssl = new NativeOpenSsl (IsServer, false, protocol);
			// FIXME
			var validationCallback = GetValidationCallback ();
			openssl.SetCertificateVerify (NativeOpenSsl.VerifyMode.SSL_VERIFY_PEER, validationCallback);
			#if FIXME
			if (!Parameters.VerifyPeerCertificate)
				openssl.SetCertificateVerify (NativeOpenSsl.VerifyMode.SSL_VERIFY_NONE, null);
			else {
				NativeOpenSsl.VerifyMode mode = NativeOpenSsl.VerifyMode.SSL_VERIFY_PEER;
				var serverParams = Parameters as IServerParameters;
				if (serverParams != null) {
					if (serverParams.RequireClientCertificate)
						mode |= NativeOpenSsl.VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
					else if (serverParams.AskForClientCertificate)
						mode |= NativeOpenSsl.VerifyMode.SSL_VERIFY_CLIENT_ONCE;
				}
				openssl.SetCertificateVerify (mode, RemoteValidationCallback);
			}
			#endif
			Initialize ();

			Task.Factory.StartNew (() => {
				try {
					CreateConnection ();
					createTcs.SetResult (null);
				} catch (Exception ex) {
					createTcs.SetException (ex);
				}
			});
			return FinishedTask;
		}

		protected abstract void Initialize ();

		protected abstract void CreateConnection ();

		public sealed override Task WaitForConnection (TestContext ctx, CancellationToken cancellationToken)
		{
			return createTcs.Task;
		}

		public sealed override Task<bool> Shutdown (TestContext ctx, bool attemptCleanShutdown, bool waitForReply, CancellationToken cancellationToken)
		{
			return Task.Run (() => {
				ctx.LogMessage ("{0} shutdown: {1} {2}", this, attemptCleanShutdown, waitForReply);
				return openssl.Shutdown (attemptCleanShutdown && waitForReply);
			});
		}

		protected override void Stop ()
		{
			if (openssl != null) {
				openssl.Dispose ();
				openssl = null;
			}
		}

		public override string ToString ()
		{
			return string.Format ("[{0}]", GetType ().Name);
		}

	}
}

