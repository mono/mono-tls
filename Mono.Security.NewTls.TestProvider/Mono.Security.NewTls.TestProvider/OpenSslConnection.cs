//
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
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Server;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.TestProvider
{
	public abstract class OpenSslConnection : Connection, ICommonConnection, IMonoCommonConnection
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

		public ConnectionProvider Provider {
			get { return provider; }
		}

		public override ProtocolVersions SupportedProtocols {
			get { return provider.SupportedProtocols; }
		}

		public Stream Stream {
			get { return openssl; }
		}

		public ISslStream SslStream {
			get { throw new NotImplementedException (); }
		}

		public IStreamInstrumentation StreamInstrumentation {
			get { return null; }
		}

		public bool SupportsConnectionInfo {
			get { return true; }
		}

		protected abstract bool IsServer {
			get;
		}

		bool IMonoCommonConnection.SupportsInstrumentation {
			get { return false; }
		}

		InstrumentationProvider IMonoCommonConnection.InstrumentationProvider {
			get { throw new NotSupportedException (); }
			set { throw new NotSupportedException (); }
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
				CipherSuiteCode = (CipherSuiteCode)openssl.CurrentCipher
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
			if (version == null)
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
			CertificateValidator validator = null;

			if (IsServer) {
				validator = (CertificateValidator)Parameters.ServerCertificateValidator;
			} else {
				validator = (CertificateValidator)Parameters.ClientCertificateValidator;
			}

			if (validator == null)
				return null;

			return (ok, cert) => {
				var errors = SslPolicyErrors.None;
				if (!ok)
					errors |= SslPolicyErrors.RemoteCertificateChainErrors;
				return validator.ValidationCallback (this, cert, null, errors);
			};
		}

		void InitDiffieHellman (NativeOpenSslProtocol protocol)
		{
			var dh = new DiffieHellmanManaged ();
			var dhparams = dh.ExportParameters (true);
			openssl.SetDhParams (dhparams.P, dhparams.G);

			// Optional: this is OpenSsl's default value.
			if (protocol == NativeOpenSslProtocol.TLS12)
				openssl.SetNamedCurve ("prime256v1");
		}

		public sealed override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			var protocol = GetProtocolVersion ();
			ctx.LogMessage ("Starting {0} version {1}.", this, protocol);
			openssl = new NativeOpenSsl (IsServer, Parameters.EnableDebugging, protocol);
			var validationCallback = GetValidationCallback ();
			openssl.SetCertificateVerify (NativeOpenSsl.VerifyMode.SSL_VERIFY_PEER, validationCallback);
			InitDiffieHellman (protocol);
			Initialize ();

			Task.Factory.StartNew (() => {
				try {
					CreateConnection (ctx);
					createTcs.SetResult (null);
				} catch (Exception ex) {
					createTcs.SetException (ex);
				}
			});
			return FinishedTask;
		}

		protected void SelectCiphers (TestContext ctx, ICollection<CipherSuiteCode> ciphers)
		{
			if (ciphers == null)
				return;

			ctx.LogDebug (2, "Select Ciphers: {0}", string.Join (":", ciphers));
			openssl.SetCipherList (ciphers);
		}

		protected abstract void Initialize ();

		protected abstract void CreateConnection (TestContext ctx);

		public sealed override Task WaitForConnection (TestContext ctx, CancellationToken cancellationToken)
		{
			return createTcs.Task;
		}

		public sealed override Task<bool> Shutdown (TestContext ctx, CancellationToken cancellationToken)
		{
			ctx.LogMessage ("{0} shutdown", this);
			return Task.Factory.FromAsync (openssl.BeginShutdown, openssl.EndShutdown, true, null);
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

