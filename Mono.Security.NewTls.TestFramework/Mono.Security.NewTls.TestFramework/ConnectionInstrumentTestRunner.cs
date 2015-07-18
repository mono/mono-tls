//
// ConnectionInstrumentTestRunner.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Resources;

namespace Mono.Security.NewTls.TestFramework
{
	public class ConnectionInstrumentTestRunner : InstrumentationTestRunner
	{
		new public ConnectionInstrumentParameters Parameters {
			get { return (ConnectionInstrumentParameters)base.Parameters; }
		}

		public ConnectionInstrumentType Type {
			get { return Parameters.Type; }
		}

		public ConnectionInstrumentTestRunner (IServer server, IClient client, ConnectionInstrumentParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
		}

		public override Instrumentation CreateInstrument (TestContext ctx)
		{
			var instrumentation = new Instrumentation ();

			var settings = new UserSettings ();

			instrumentation.SettingsInstrument = new ConnectionInstrument (settings, ctx, this);
			instrumentation.EventSink = new ConnectionEventSink (ctx, this);

			if (Parameters.HandshakeInstruments != null)
				instrumentation.HandshakeInstruments.UnionWith (Parameters.HandshakeInstruments);

			return instrumentation;
		}

		public static IEnumerable<ConnectionInstrumentParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			return GetInstrumentationTypes (ctx, category).Select (t => Create (ctx, category, t));
		}

		public static IEnumerable<ConnectionInstrumentType> GetInstrumentationTypes (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.ClientConnection:
				yield return ConnectionInstrumentType.FragmentHandshakeMessages;
				yield return ConnectionInstrumentType.SendBlobAfterReceivingFinish;
				break;

			case InstrumentationCategory.ServerConnection:
				yield return ConnectionInstrumentType.FragmentHandshakeMessages;
				break;

			case InstrumentationCategory.Connection:
				yield return ConnectionInstrumentType.FragmentHandshakeMessages;
				break;

			case InstrumentationCategory.ClientRenegotiation:
				// yield return ConnectionInstrumentType.RequestClientRenegotiation;
				break;

			case InstrumentationCategory.ServerRenegotiation:
				yield return ConnectionInstrumentType.RequestRenegotiation;
				yield return ConnectionInstrumentType.SendBlobBeforeHelloRequest;
				yield return ConnectionInstrumentType.SendBlobAfterHelloRequest;
				yield return ConnectionInstrumentType.SendBlobBeforeAndAfterHelloRequest;
				yield return ConnectionInstrumentType.SendDuplicateHelloRequest;
				yield return ConnectionInstrumentType.RequestServerRenegotiation;
				yield return ConnectionInstrumentType.RequestServerRenegotiationWithPendingRead;
				break;

			case InstrumentationCategory.Renegotiation:
				yield return ConnectionInstrumentType.SendBlobBeforeRenegotiatingHello;
				yield return ConnectionInstrumentType.SendBlobBeforeRenegotiatingHelloNoPendingRead;
				break;

			case InstrumentationCategory.MartinTest:
				yield return ConnectionInstrumentType.MartinTest;
				break;

			case InstrumentationCategory.ManualClient:
				yield return ConnectionInstrumentType.MartinClientPuppy;
				break;

			case InstrumentationCategory.ManualServer:
				yield return ConnectionInstrumentType.MartinServerPuppy;
				break;

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				break;
			}
		}

		static ConnectionInstrumentParameters CreateParameters (InstrumentationCategory category, ConnectionInstrumentType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new ConnectionInstrumentParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		static ConnectionInstrumentParameters Create (TestContext ctx, InstrumentationCategory category, ConnectionInstrumentType type)
		{
			var parameters = CreateParameters (category, type);

			switch (type) {
			case ConnectionInstrumentType.FragmentHandshakeMessages:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] { HandshakeInstrumentType.FragmentHandshakeMessages };
				break;

			case ConnectionInstrumentType.SendBlobAfterReceivingFinish:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] { HandshakeInstrumentType.SendBlobAfterReceivingFinish };
				break;

			case ConnectionInstrumentType.RequestRenegotiation:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation
				};
				break;

			case ConnectionInstrumentType.SendBlobBeforeHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendBlobBeforeHelloRequest
				};
				break;

			case ConnectionInstrumentType.SendBlobAfterHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendBlobAfterHelloRequest
				};
				break;

			case ConnectionInstrumentType.SendBlobBeforeAndAfterHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendBlobBeforeHelloRequest,
					HandshakeInstrumentType.SendBlobAfterHelloRequest
				};
				break;

			case ConnectionInstrumentType.SendDuplicateHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendDuplicateHelloRequest
				};
				break;

			case ConnectionInstrumentType.RequestServerRenegotiation:
				parameters.RequestServerRenegotiation = true;
				break;

			case ConnectionInstrumentType.RequestServerRenegotiationWithPendingRead:
				parameters.RequestServerRenegotiation = true;
				parameters.QueueServerReadFirst = true;
				break;

			case ConnectionInstrumentType.SendBlobBeforeRenegotiatingHello:
				parameters.RequestServerRenegotiation = true;
				parameters.QueueServerReadFirst = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello
				};
				break;

			case ConnectionInstrumentType.SendBlobBeforeRenegotiatingHelloNoPendingRead:
				parameters.RequestServerRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello
				};
				break;

			case ConnectionInstrumentType.RequestClientRenegotiation:
				parameters.RequestClientRenegotiation = true;
				break;

			case ConnectionInstrumentType.MartinTest:
				parameters.RequestClientRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
				};
				parameters.EnableDebugging = true;
				break;

			case ConnectionInstrumentType.MartinClientPuppy:
			case ConnectionInstrumentType.MartinServerPuppy:
				goto case ConnectionInstrumentType.MartinTest;

			default:
				ctx.AssertFail ("Unsupported connection instrument: '{0}'.", type);
				break;
			}

			return parameters;
		}

		public bool HasInstrument (HandshakeInstrumentType type)
		{
			return Parameters.HandshakeInstruments != null && Parameters.HandshakeInstruments.Contains (type);
		}

		protected override async Task HandleClient (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Parameters.RequestClientRenegotiation) {
				LogDebug (ctx, 1, "HandleClient - waiting for renegotiation");
				var monoSslStream = (IMonoSslStream)Client.SslStream;
				await monoSslStream.RequestRenegotiation ();
				LogDebug (ctx, 1, "HandleClient - done waiting for renegotiation");
			}

			LogDebug (ctx, 1, "HandleClient");

			if (HasInstrument (HandshakeInstrumentType.SendBlobBeforeHelloRequest))
				await ExpectBlob (ctx, Client, HandshakeInstrumentType.SendBlobBeforeHelloRequest, cancellationToken);

			if (HasInstrument (HandshakeInstrumentType.SendBlobAfterHelloRequest))
				await ExpectBlob (ctx, Client, HandshakeInstrumentType.SendBlobAfterHelloRequest, cancellationToken);

			await ExpectBlob (ctx, Client, HandshakeInstrumentType.TestCompleted, cancellationToken);

			cancellationToken.ThrowIfCancellationRequested ();

			LogDebug (ctx, 1, "HandleClient #1");

			var blob = Instrumentation.GetTextBuffer (HandshakeInstrumentType.TestCompleted);
			await Client.Stream.WriteAsync (blob.Buffer, blob.Offset, blob.Size, cancellationToken);

			LogDebug (ctx, 1, "HandleClient done");
		}

		protected override async Task HandleServerRead (TestContext ctx, CancellationToken cancellationToken)
		{
			LogDebug (ctx, 1, "HandleServerRead");

			if (HasInstrument (HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello))
				await ExpectBlob (ctx, Server, HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello, cancellationToken);

			if (HasInstrument (HandshakeInstrumentType.SendBlobAfterReceivingFinish))
				await ExpectBlob (ctx, Server, HandshakeInstrumentType.SendBlobAfterReceivingFinish, cancellationToken);

			await ExpectBlob (ctx, Server, HandshakeInstrumentType.TestCompleted, cancellationToken);

			LogDebug (ctx, 1, "HandleServerRead done");
		}

		protected override async Task HandleServerWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			LogDebug (ctx, 1, "HandleServerWrite");

			if (HasInstrument (HandshakeInstrumentType.RequestServerRenegotiation)) {
				LogDebug (ctx, 1, "HandleServerWrite - waiting for renegotiation");
				await renegotiationTcs.Task;
				LogDebug (ctx, 1, "HandleServerWrite - done waiting for renegotiation");
			}

			var blob = Instrumentation.GetTextBuffer (HandshakeInstrumentType.TestCompleted);
			await Server.Stream.WriteAsync (blob.Buffer, blob.Offset, blob.Size, cancellationToken);

			LogDebug (ctx, 1, "HandleServerWrite done");
		}

		protected override async Task HandleServer (TestContext ctx, CancellationToken cancellationToken)
		{
			Task readTask = null;

			if (Parameters.QueueServerReadFirst)
				readTask = HandleServerRead (ctx, cancellationToken);

			if (Parameters.RequestServerRenegotiation) {
				LogDebug (ctx, 1, "HandleServer - waiting for renegotiation");
				var monoSslStream = (IMonoSslStream)Server.SslStream;
				await monoSslStream.RequestRenegotiation ();
				LogDebug (ctx, 1, "HandleServer - done waiting for renegotiation");
			}

			if (readTask == null)
				readTask = HandleServerRead (ctx, cancellationToken);

			var writeTask = HandleServerWrite (ctx, cancellationToken);

			var t1 = readTask.ContinueWith (t => {
				LogDebug (ctx, 1, "Read done", t.Status, t.IsFaulted, t.IsCanceled);
				if (t.IsFaulted || t.IsCanceled)
					Client.Dispose ();
			});
			var t2 = writeTask.ContinueWith (t => {
				LogDebug (ctx, 1, "Write done", t.Status, t.IsFaulted, t.IsCanceled);
				if (t.IsFaulted || t.IsCanceled)
					Client.Dispose ();
			});

			LogDebug (ctx, 1, "HandleServer");

			await Task.WhenAll (readTask, writeTask, t1, t2);

			LogDebug (ctx, 1, "HandleServer done");
		}

		TaskCompletionSource<bool> renegotiationTcs;

		public override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			renegotiationTcs = new TaskCompletionSource<bool> ();
			return base.Start (ctx, cancellationToken);
		}

		public override async Task<bool> Shutdown (TestContext ctx, bool attemptCleanShutdown, CancellationToken cancellationToken)
		{
			renegotiationTcs.TrySetCanceled ();
			LogDebug (ctx, 1, "Shutdown", attemptCleanShutdown);
			try {
				return await base.Shutdown (ctx, attemptCleanShutdown, cancellationToken);
			} finally {
				LogDebug (ctx, 1, "Shutdown done");
			}
		}

		void OnRenegotiationCompleted (TestContext ctx)
		{
			LogDebug (ctx, 1, "OnRenegotiationCompleted");
			renegotiationTcs.SetResult (true);
		}

		class ConnectionEventSink : InstrumentationEventSink
		{
			public TestContext Context {
				get;
				private set;
			}

			public ConnectionInstrumentTestRunner Runner {
				get;
				private set;
			}

			public ConnectionEventSink (TestContext ctx, ConnectionInstrumentTestRunner runner)
			{
				Context = ctx;
				Runner = runner;
			}

			public void RenegotiationCompleted ()
			{
				Runner.OnRenegotiationCompleted (Context);
			}
		}
	}
}

