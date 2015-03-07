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
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;
using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.TestProvider
{
	public abstract class OpenSslConnection : Connection, ICommonConnection
	{
		public override bool SupportsCleanShutdown {
			get { return true; }
		}

		public OpenSslConnection (IPEndPoint endpoint, IConnectionParameters parameters)
			: base (endpoint, parameters)
		{
			createTcs = new TaskCompletionSource<object> ();
		}

		protected NativeOpenSsl openssl;
		TlsConnectionInfo connectionInfo;
		TaskCompletionSource<object> createTcs;

		public Stream Stream {
			get { return openssl; }
		}

		public override bool SupportsConnectionInfo {
			get { return true; }
		}

		public override TlsConnectionInfo GetConnectionInfo ()
		{
			if (connectionInfo != null)
				return connectionInfo;

			connectionInfo = new TlsConnectionInfo {
				CipherCode = (CipherSuiteCode)openssl.CurrentCipher
			};

			return connectionInfo;
		}

		public sealed override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			openssl = new NativeOpenSsl (this is IClient, Parameters.EnableDebugging);
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

		public sealed override Task WaitForConnection ()
		{
			return createTcs.Task;
		}

		public sealed override Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply)
		{
			return Task.Run (() => {
				return openssl.Shutdown (waitForReply);
			});
		}

		protected override void Stop ()
		{
			if (openssl != null) {
				openssl.Dispose ();
				openssl = null;
			}
		}

	}
}

