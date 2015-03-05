//
// DotNetConnection.cs
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
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls;
using Mono.Security.NewTls.TestFramework;
using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.TestProvider
{
	public abstract class DotNetConnection : Connection, ICommonConnection
	{
		public DotNetConnection (IPEndPoint endpoint, IConnectionParameters parameters)
			: base (endpoint, parameters)
		{
		}

		Socket socket;
		Socket accepted;
		TaskCompletionSource<Stream> tcs;

		Stream sslStream;

		protected bool RemoteValidationCallback (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
		{
			Debug ("REMOTE VALIDATION CALLBACK: {0} {1}", certificate.Subject, errors);
			return RemoteValidationCallback (errors == SslPolicyErrors.None, certificate);
		}

		protected X509Certificate LocalCertificateSelectionCallback (object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
		{
			Debug ("LOCAL SELECTION CALLBACK: {0}", targetHost);
			return LocalCertificateSelectionCallback (targetHost, localCertificates, remoteCertificate, acceptableIssuers);
		}

		public Stream Stream {
			get { return sslStream; }
		}

		public override bool SupportsCleanShutdown {
			get { return false; }
		}

		public override TlsConnectionInfo GetConnectionInfo ()
		{
			throw new InvalidOperationException ();
		}

		protected abstract Stream Start (TestContext ctx, Socket socket);

		public sealed override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			if (this is IClient)
				StartClient (ctx, cancellationToken);
			else
				StartServer (ctx, cancellationToken);
			return FinishedTask;
		}

		void StartServer (TestContext ctx, CancellationToken cancellationToken)
		{
			socket = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			socket.Bind (EndPoint);
			socket.Listen (1);

			tcs = new TaskCompletionSource<Stream> ();

			socket.BeginAccept (ar => {
				try {
					accepted = socket.EndAccept (ar);
					sslStream = Start (ctx, accepted);
					tcs.SetResult (sslStream);
				} catch (Exception ex) {
					ctx.LogError ("Error starting server", ex);
					Debug ("Error starting server: {0}", ex);
					tcs.SetException (ex);
				}
			}, null);
		}

		void StartClient (TestContext ctx, CancellationToken cancellationToken)
		{
			socket = new Socket (AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

			tcs = new TaskCompletionSource<Stream> ();

			socket.BeginConnect (EndPoint, ar => {
				try {
					socket.EndConnect (ar);
					sslStream = Start (ctx, socket);
					tcs.SetResult (sslStream);
				} catch (Exception ex) {
					ctx.LogError ("Error starting client", ex);
					Debug ("Error starting client: {0}", ex);
					tcs.SetException (ex);
				}
			}, null);
		}

		public sealed override Task WaitForConnection ()
		{
			return tcs.Task;
		}

		protected virtual Task<bool> TryCleanShutdown (bool waitForReply)
		{
			throw new NotSupportedException ("Clean shutdown not supported yet.");
		}

		public sealed override async Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply)
		{
			if (attemptCleanShutdown)
				attemptCleanShutdown = await TryCleanShutdown (waitForReply);

			return attemptCleanShutdown;
		}

		protected override void Stop ()
		{
			if (accepted != null) {
				try {
					accepted.Shutdown (SocketShutdown.Both);
				} catch {
					;
				}
				try {
					accepted.Dispose ();
				} catch {
					;
				}
				accepted = null;
			}
			if (socket != null) {
				try {
					socket.Shutdown (SocketShutdown.Both);
				} catch {
					;
				}
				try {
					socket.Dispose ();
				} catch {
					;
				}
				socket = null;
			}
			try {
				if (sslStream != null) {
					sslStream.Dispose ();
					sslStream = null;
				}
			} catch {
				;
			}
		}

	}
}

