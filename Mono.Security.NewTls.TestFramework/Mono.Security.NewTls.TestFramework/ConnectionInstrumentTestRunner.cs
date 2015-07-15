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
			switch (category) {
			case InstrumentationCategory.ClientConnection:
				return ClientConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.ServerConnection:
				return ServerConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.ServerRenegotiation:
				return ServerRenegotiationTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.Connection:
				return ConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.MartinTest:
				return MartinTestTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.ManualClient:
				return ManualClientTestTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.ManualServer:
				return ManualServerTestTypes.Select (t => Create (ctx, category, t));

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				return null;
			}
		}

		internal static readonly ConnectionInstrumentType[] ClientConnectionTypes = {
			ConnectionInstrumentType.FragmentHandshakeMessages,
			ConnectionInstrumentType.SendBlobAfterReceivingFinish
		};

		internal static readonly ConnectionInstrumentType[] ServerConnectionTypes = {
			ConnectionInstrumentType.FragmentHandshakeMessages
		};

		internal static readonly ConnectionInstrumentType[] ServerRenegotiationTypes = {
			ConnectionInstrumentType.RequestRenegotiation,
			ConnectionInstrumentType.SendBlobBeforeHelloRequest,
			ConnectionInstrumentType.SendBlobAfterHelloRequest,
			ConnectionInstrumentType.SendBlobBeforeAndAfterHelloRequest,
			ConnectionInstrumentType.SendDuplicateHelloRequest
		};

		internal static readonly ConnectionInstrumentType[] ConnectionTypes = {
			ConnectionInstrumentType.FragmentHandshakeMessages
		};

		internal static readonly ConnectionInstrumentType[] MartinTestTypes = {
			ConnectionInstrumentType.MartinTest
		};

		internal static readonly ConnectionInstrumentType[] ManualClientTestTypes = {
			ConnectionInstrumentType.MartinClientPuppy
		};

		internal static readonly ConnectionInstrumentType[] ManualServerTestTypes = {
			ConnectionInstrumentType.MartinServerPuppy
		};

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
				parameters.RequestRenegotiation = true;
				break;

			case ConnectionInstrumentType.SendBlobBeforeHelloRequest:
				parameters.RequestRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobBeforeHelloRequest
				};
				break;

			case ConnectionInstrumentType.SendBlobAfterHelloRequest:
				parameters.RequestRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobAfterHelloRequest
				};
				break;

			case ConnectionInstrumentType.SendBlobBeforeAndAfterHelloRequest:
				parameters.RequestRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobBeforeHelloRequest,
					HandshakeInstrumentType.SendBlobAfterHelloRequest
				};
				break;

			case ConnectionInstrumentType.SendDuplicateHelloRequest:
				parameters.RequestRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendDuplicateHelloRequest
				};
				break;

			case ConnectionInstrumentType.MartinTest:
				// parameters.RequestRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation
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

		protected override async Task OnRun (TestContext ctx, CancellationToken cancellationToken)
		{
			if (HasInstrument (HandshakeInstrumentType.RequestServerRenegotiation)) {
				ctx.LogMessage ("Calling IMonoSslStream.RequestRenegotiation()");
				var monoSslStream = (IMonoSslStream)Server.SslStream;
				await monoSslStream.RequestRenegotiation ();
				ctx.LogMessage ("Done calling IMonoSslStream.RequestRenegotiation()");
			}

			await base.OnRun (ctx, cancellationToken);
		}

		protected override Task MainLoop (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Category == InstrumentationCategory.ServerRenegotiation)
				return RunNewMainLoop (ctx, cancellationToken);

			switch (Parameters.Type) {
			case ConnectionInstrumentType.SendBlobAfterReceivingFinish:
				return RunMainLoopBlob (ctx, HandshakeInstrumentType.SendBlobAfterReceivingFinish, cancellationToken);

			case ConnectionInstrumentType.MartinTest:
			case ConnectionInstrumentType.MartinClientPuppy:
			case ConnectionInstrumentType.MartinServerPuppy:
				return RunNewMainLoop (ctx, cancellationToken);

			default:
				return base.MainLoop (ctx, cancellationToken);
			}
		}

		async Task RunMainLoopBlob (TestContext ctx, HandshakeInstrumentType type, CancellationToken cancellationToken)
		{
			var expected = Instrumentation.GetTextBuffer (type).GetBuffer ();

			var buffer = new byte [4096];
			int ret = await Server.Stream.ReadAsync (buffer, 0, buffer.Length);
			ctx.Assert (ret, Is.EqualTo (expected.Length));

			buffer = new BufferOffsetSize (buffer, 0, ret).GetBuffer ();

			ctx.Assert (buffer, Is.EqualTo (expected), "blob");

			await Shutdown (ctx, SupportsCleanShutdown, cancellationToken);
		}

		static async Task ExpectBlob (TestContext ctx, Stream stream, HandshakeInstrumentType type, CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested ();

			var buffer = new byte [4096];
			var blob = Instrumentation.GetTextBuffer (type);
			var ret = await stream.ReadAsync (buffer, 0, buffer.Length, cancellationToken);
			ctx.Assert (ret, Is.GreaterThan (0), "read success");
			var result = new BufferOffsetSize (buffer, 0, ret);

			ctx.Expect (result, new IsEqualBlob (blob), "blob");
		}

		async Task HandleClient (TestContext ctx, CancellationToken cancellationToken)
		{
			if ((ConnectionFlags & MonoConnectionFlags.ManualClient) != 0)
				return;

			cancellationToken.ThrowIfCancellationRequested ();

			if (HasInstrument (HandshakeInstrumentType.SendBlobBeforeHelloRequest))
				await ExpectBlob (ctx, Client.Stream, HandshakeInstrumentType.SendBlobBeforeHelloRequest, cancellationToken);
			if (HasInstrument (HandshakeInstrumentType.SendBlobAfterHelloRequest))
				await ExpectBlob (ctx, Client.Stream, HandshakeInstrumentType.SendBlobAfterHelloRequest, cancellationToken);

			await ExpectBlob (ctx, Client.Stream, HandshakeInstrumentType.TestCompleted, cancellationToken);

			cancellationToken.ThrowIfCancellationRequested ();

			var blob = Instrumentation.GetTextBuffer (HandshakeInstrumentType.TestCompleted);
			await Client.Stream.WriteAsync (blob.Buffer, blob.Offset, blob.Size, cancellationToken);

			await Client.Shutdown (ctx, SupportsCleanShutdown, cancellationToken);
		}

		async Task HandleServerRead (TestContext ctx, CancellationToken cancellationToken)
		{
			await ExpectBlob (ctx, Server.Stream, HandshakeInstrumentType.TestCompleted, cancellationToken);
		}

		async Task HandleServerWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			await renegotiationTcs.Task;

			var blob = Instrumentation.GetTextBuffer (HandshakeInstrumentType.TestCompleted);
			await Server.Stream.WriteAsync (blob.Buffer, blob.Offset, blob.Size, cancellationToken);

			await Server.Shutdown (ctx, SupportsCleanShutdown, cancellationToken);
		}

		async Task HandleServer (TestContext ctx, CancellationToken cancellationToken)
		{
			var readTask = HandleServerRead (ctx, cancellationToken);
			var writeTask = HandleServerWrite (ctx, cancellationToken);

			await Task.WhenAll (readTask, writeTask);
		}

		async Task RunNewMainLoop (TestContext ctx, CancellationToken cancellationToken)
		{
			cancellationToken.ThrowIfCancellationRequested ();

			var clientTask = HandleClient (ctx, cancellationToken);
			var serverTask = HandleServer (ctx, cancellationToken);

			await Task.WhenAll (clientTask, serverTask);
		}

		TaskCompletionSource<bool> renegotiationTcs;

		public override Task Start (TestContext ctx, CancellationToken cancellationToken)
		{
			renegotiationTcs = new TaskCompletionSource<bool> ();
			return base.Start (ctx, cancellationToken);
		}

		public override Task<bool> Shutdown (TestContext ctx, bool attemptCleanShutdown, CancellationToken cancellationToken)
		{
			renegotiationTcs.TrySetCanceled ();
			return base.Shutdown (ctx, attemptCleanShutdown, cancellationToken);
		}

		void OnRenegotiationCompleted (TestContext ctx)
		{
			ctx.LogMessage ("ON RENEGOTIATION COMPLETED");
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

