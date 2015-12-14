//
// RenegotiationInstrumentConnectionHandler.cs
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
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Resources;

namespace Mono.Security.NewTls.TestFramework
{
	using ConnectionFramework;

	public class RenegotiationInstrumentConnectionHandler : ConnectionInstrumentConnectionHandler
	{
		new public RenegotiationInstrumentTestRunner Runner {
			get { return (RenegotiationInstrumentTestRunner)base.Runner; }
		}

		new public RenegotiationInstrumentParameters Parameters {
			get { return (RenegotiationInstrumentParameters)base.Parameters; }
		}

		public RenegotiationInstrumentConnectionHandler (RenegotiationInstrumentTestRunner runner)
			: base (runner)
		{
			renegotiationStartedTcs = new TaskCompletionSource<bool> ();
			renegotiationCompletedTcs = new TaskCompletionSource<bool> ();
		}

		TaskCompletionSource<bool> renegotiationStartedTcs;
		TaskCompletionSource<bool> renegotiationCompletedTcs;

		protected override bool NeedCustomCertificateSelectionCallback {
			get { return Parameters.NeedCustomCertificateSelectionCallback; }
		}

		protected override X509Certificate OnCertificateSelectionCallback (
			TestContext ctx, string targetHost, X509CertificateCollection localCertificates,
			X509Certificate remoteCertificate, string[] acceptableIssuers)
		{
			LogDebug (ctx, 1, "CertificateSelectionCallback", renegotiationStartedTcs.Task.Status, targetHost,
				localCertificates != null ? localCertificates.Count : -1, remoteCertificate,
				acceptableIssuers != null ? acceptableIssuers.Length : -1);
			if (renegotiationStartedTcs.Task.IsCompleted) {
				ctx.Assert (remoteCertificate, Is.Not.Null, "have remote certificate");
				return ResourceManager.MonkeyCertificate;
			} else {
				ctx.Assert (remoteCertificate, Is.Null, "first call");
				return null;
			}
		}

		protected override async Task HandleClientRead (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Runner.HasInstrument (HandshakeInstrumentType.SendBlobBeforeHelloRequest))
				await ExpectBlob (ctx, Client, HandshakeInstrumentType.SendBlobBeforeHelloRequest, cancellationToken);

			if (Runner.HasInstrument (HandshakeInstrumentType.SendBlobAfterHelloRequest))
				await ExpectBlob (ctx, Client, HandshakeInstrumentType.SendBlobAfterHelloRequest, cancellationToken);

			await base.HandleClientRead (ctx, cancellationToken);
		}

		protected override async Task HandleServerRead (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Runner.HasInstrument (HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello))
				await ExpectBlob (ctx, Server, HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello, cancellationToken);

			await base.HandleServerRead (ctx, cancellationToken);
		}

		protected override async Task HandleServerWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Runner.HasInstrument (HandshakeInstrumentType.RequestServerRenegotiation)) {
				LogDebug (ctx, 1, "HandleServerWrite - waiting for renegotiation");
				await renegotiationCompletedTcs.Task;
				LogDebug (ctx, 1, "HandleServerWrite - done waiting for renegotiation");
			}

			if (Parameters.ServerWriteDuringClientRenegotiation) {
				if (Server.StreamInstrumentation != null) {
					var readTcs = new TaskCompletionSource<object> ();
					Server.StreamInstrumentation.OnNextRead (() => {
						LogDebug (ctx, 1, "HandleServerWrite - next read");
						readTcs.SetResult (null);
						return null;
					}, null);
					Server.StreamInstrumentation.OnNextWrite (async () => {
						LogDebug (ctx, 1, "HandleServerWrite - next write");
						StartServerRead ();
						await readTcs.Task;
					}, async () => {
						LogDebug (ctx, 1, "HandleServerWrite - next write #1");
						await renegotiationStartedTcs.Task;
						LogDebug (ctx, 1, "HandleServerWrite - next write #2");
						await Task.Delay (1000);
						LogDebug (ctx, 1, "HandleServerWrite - next write #3");
					});
				} else {
					StartServerRead ();
				}
			}

			await base.HandleServerWrite (ctx, cancellationToken);
		}

		protected override async Task HandleClient (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Parameters.RequestClientRenegotiation) {
				LogDebug (ctx, 1, "HandleClient - waiting for renegotiation");
				var extension = Client.Provider.GetTlsProviderExtension ();
				await extension.RequestRenegotiation ((IMonoSslStream)Client.SslStream);
				LogDebug (ctx, 1, "HandleClient - done waiting for renegotiation");

				if (!Parameters.ServerWriteDuringClientRenegotiation)
					StartServerWrite ();
			}

			StartClientRead ();
		}

		protected override async Task HandleServer (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Parameters.QueueServerReadFirst)
				StartServerRead ();

			if (Parameters.RequestServerRenegotiation) {
				LogDebug (ctx, 1, "HandleServer - waiting for renegotiation");
				var extension = Server.Provider.GetTlsProviderExtension ();
				await extension.RequestRenegotiation ((IMonoSslStream)Server.SslStream);
				LogDebug (ctx, 1, "HandleServer - done waiting for renegotiation");
			}

			if (Parameters.ServerWriteDuringClientRenegotiation) {
				StartServerWrite ();
			} else {
				if (!Parameters.RequestClientRenegotiation)
					StartServerWrite ();

				if (!Parameters.QueueServerReadFirst)
					StartServerRead ();
			}
		}

		protected override void OnShutdown (TestContext ctx)
		{
			renegotiationCompletedTcs.TrySetCanceled ();
		}

		internal void OnRenegotiationStarted (TestContext ctx, bool server)
		{
			LogDebug (ctx, 1, "OnRenegotiationStarted", server, renegotiationStartedTcs.Task.IsCompleted);
			renegotiationStartedTcs.TrySetResult (true);
		}

		internal void OnRenegotiationCompleted (TestContext ctx, bool server)
		{
			LogDebug (ctx, 1, "OnRenegotiationCompleted", server, renegotiationCompletedTcs.Task.IsCompleted);
			renegotiationCompletedTcs.TrySetResult (server);
		}

		protected override void DoDispose ()
		{
			renegotiationStartedTcs.TrySetCanceled ();
			renegotiationCompletedTcs.TrySetCanceled ();
			base.DoDispose ();
		}
	}
}

