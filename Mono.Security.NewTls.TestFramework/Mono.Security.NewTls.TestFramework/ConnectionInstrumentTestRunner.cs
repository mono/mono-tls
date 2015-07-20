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
using Xamarin.WebTests.Providers;
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

		TaskCompletionSource<bool> renegotiationStartedTcs;
		TaskCompletionSource<bool> renegotiationCompletedTcs;
		TaskCompletionSource<bool> serverReadTcs;
		TaskCompletionSource<bool> serverWriteTcs;
		TaskCompletionSource<bool> clientReadTcs;
		TaskCompletionSource<bool> clientWriteTcs;

		public ConnectionInstrumentTestRunner (IServer server, IClient client, ConnectionInstrumentParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
			renegotiationStartedTcs = new TaskCompletionSource<bool> ();
			renegotiationCompletedTcs = new TaskCompletionSource<bool> ();
			serverReadTcs = new TaskCompletionSource<bool> ();
			serverWriteTcs = new TaskCompletionSource<bool> ();
			clientReadTcs = new TaskCompletionSource<bool> ();
			clientWriteTcs = new TaskCompletionSource<bool> ();
		}

		public static bool IsSupported (ConnectionInstrumentParameters parameters, ConnectionProviderType clientType, ConnectionProviderType serverType)
		{
			if (parameters.ServerWriteDuringClientRenegotiation && serverType == ConnectionProviderType.OpenSsl)
				return false;

			return true;
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
				yield return ConnectionInstrumentType.RequestClientRenegotiation;
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
				yield return ConnectionInstrumentType.RequestClientRenegotiationWithPendingWrite;
				break;

			case InstrumentationCategory.MartinTest:
			case InstrumentationCategory.MartinTestClient:
			case InstrumentationCategory.MartinTestServer:
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

			case ConnectionInstrumentType.RequestClientRenegotiationWithPendingWrite:
				parameters.RequestClientRenegotiation = true;
				parameters.ServerWriteDuringClientRenegotiation = true;
				parameters.ServerParameters.UseStreamInstrumentation = true;
				break;

			case ConnectionInstrumentType.MartinTest:
				parameters.RequestClientRenegotiation = true;
				parameters.ServerWriteDuringClientRenegotiation = true;
				parameters.ServerParameters.UseStreamInstrumentation = true;
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

		protected override async Task HandleClientRead (TestContext ctx, CancellationToken cancellationToken)
		{
			await clientReadTcs.Task;
			cancellationToken.ThrowIfCancellationRequested ();

			LogDebug (ctx, 1, "HandleClientRead");

			if (HasInstrument (HandshakeInstrumentType.SendBlobBeforeHelloRequest))
				await ExpectBlob (ctx, Client, HandshakeInstrumentType.SendBlobBeforeHelloRequest, cancellationToken);

			if (HasInstrument (HandshakeInstrumentType.SendBlobAfterHelloRequest))
				await ExpectBlob (ctx, Client, HandshakeInstrumentType.SendBlobAfterHelloRequest, cancellationToken);

			await base.HandleClientRead (ctx, cancellationToken);

			clientWriteTcs.SetResult (true);
		}

		protected override async Task HandleClientWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			await clientWriteTcs.Task;
			cancellationToken.ThrowIfCancellationRequested ();

			LogDebug (ctx, 1, "HandleClientWrite");

			await base.HandleClientWrite (ctx, cancellationToken);
		}

		protected override async Task HandleServerRead (TestContext ctx, CancellationToken cancellationToken)
		{
			await serverReadTcs.Task;
			cancellationToken.ThrowIfCancellationRequested ();

			LogDebug (ctx, 1, "HandleServerRead");
			if (HasInstrument (HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello))
				await ExpectBlob (ctx, Server, HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello, cancellationToken);

			if (HasInstrument (HandshakeInstrumentType.SendBlobAfterReceivingFinish))
				await ExpectBlob (ctx, Server, HandshakeInstrumentType.SendBlobAfterReceivingFinish, cancellationToken);

			await base.HandleServerRead (ctx, cancellationToken);
		}

		protected override async Task HandleServerWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			await serverWriteTcs.Task;
			cancellationToken.ThrowIfCancellationRequested ();

			LogDebug (ctx, 1, "HandleServerWrite");

			if (HasInstrument (HandshakeInstrumentType.RequestServerRenegotiation)) {
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
						serverReadTcs.SetResult (true);
						await readTcs.Task;
					}, async () => {
						LogDebug (ctx, 1, "HandleServerWrite - next write #1");
						await renegotiationStartedTcs.Task;
						LogDebug (ctx, 1, "HandleServerWrite - next write #2");
						await Task.Delay (1000);
						LogDebug (ctx, 1, "HandleServerWrite - next write #3");
					});
				} else {
					serverReadTcs.SetResult (true);
				}
			}

			await base.HandleServerWrite (ctx, cancellationToken);
		}

		protected override async Task OnHandleClient (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Parameters.RequestClientRenegotiation) {
				LogDebug (ctx, 1, "HandleClient - waiting for renegotiation");
				var monoSslStream = (IMonoSslStream)Client.SslStream;
				await monoSslStream.RequestRenegotiation ();
				LogDebug (ctx, 1, "HandleClient - done waiting for renegotiation");

				if (!Parameters.ServerWriteDuringClientRenegotiation)
					serverWriteTcs.SetResult (false);
			}

			clientReadTcs.SetResult (true);

			await base.OnHandleClient (ctx, cancellationToken);
		}

		protected override async Task OnHandleServer (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Parameters.QueueServerReadFirst)
				serverReadTcs.SetResult (true);

			if (Parameters.RequestServerRenegotiation) {
				LogDebug (ctx, 1, "HandleServer - waiting for renegotiation");
				var monoSslStream = (IMonoSslStream)Server.SslStream;
				await monoSslStream.RequestRenegotiation ();
				LogDebug (ctx, 1, "HandleServer - done waiting for renegotiation");
			}

			if (Parameters.ServerWriteDuringClientRenegotiation) {
				serverWriteTcs.SetResult (true);
			} else {
				if (!Parameters.RequestClientRenegotiation)
					serverWriteTcs.SetResult (true);

				if (!Parameters.QueueServerReadFirst)
					serverReadTcs.SetResult (false);
			}

			await base.OnHandleServer (ctx, cancellationToken);
		}

		public override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			return base.Start (ctx, cancellationToken);
		}

		public override async Task<bool> Shutdown (TestContext ctx, CancellationToken cancellationToken)
		{
			renegotiationCompletedTcs.TrySetCanceled ();
			LogDebug (ctx, 1, "Shutdown");
			try {
				return await base.Shutdown (ctx, cancellationToken);
			} finally {
				LogDebug (ctx, 1, "Shutdown done");
			}
		}

		void OnRenegotiationStarted (TestContext ctx, bool server)
		{
			LogDebug (ctx, 1, "OnRenegotiationStarted", server, renegotiationStartedTcs.Task.IsCompleted);
			renegotiationStartedTcs.TrySetResult (true);
		}

		void OnRenegotiationCompleted (TestContext ctx, bool server)
		{
			LogDebug (ctx, 1, "OnRenegotiationCompleted", server, renegotiationCompletedTcs.Task.IsCompleted);
			renegotiationCompletedTcs.TrySetResult (server);
		}

		protected override void Dispose (bool disposing)
		{
			renegotiationStartedTcs.TrySetCanceled ();
			renegotiationCompletedTcs.TrySetCanceled ();
			serverReadTcs.TrySetCanceled ();
			serverWriteTcs.TrySetCanceled ();
			clientReadTcs.TrySetCanceled ();
			clientWriteTcs.TrySetCanceled ();
			base.Dispose (disposing);
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

			public void StartRenegotiation (ITlsContext context)
			{
				Runner.OnRenegotiationStarted (Context, context.IsServer);
			}

			public void RenegotiationCompleted (ITlsContext context)
			{
				Runner.OnRenegotiationCompleted (Context, context.IsServer);
			}
		}
	}
}

