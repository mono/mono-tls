//
// RenegotiationInstrumentTestRunner.cs
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
	public class RenegotiationInstrumentTestRunner : ConnectionInstrumentTestRunner
	{
		new public RenegotiationInstrumentParameters Parameters {
			get { return (RenegotiationInstrumentParameters)base.Parameters; }
		}

		public RenegotiationInstrumentType Type {
			get { return Parameters.Type; }
		}

		TaskCompletionSource<bool> renegotiationStartedTcs;
		TaskCompletionSource<bool> renegotiationCompletedTcs;

		public RenegotiationInstrumentTestRunner (IServer server, IClient client, RenegotiationInstrumentParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
			renegotiationStartedTcs = new TaskCompletionSource<bool> ();
			renegotiationCompletedTcs = new TaskCompletionSource<bool> ();
		}

		protected override ConnectionInstrument CreateConnectionInstrument (TestContext ctx, UserSettings settings)
		{
			var instrument = base.CreateConnectionInstrument (ctx, settings);
			instrument.EventSink = new MyEventSink (ctx, (RenegotiationInstrumentConnectionHandler)ConnectionHandler);
			return instrument;
		}

		protected override InstrumentationConnectionHandler CreateConnectionHandler ()
		{
			return new RenegotiationInstrumentConnectionHandler (this);
		}

		public static bool IsSupported (RenegotiationInstrumentParameters parameters, ConnectionProviderType clientType, ConnectionProviderType serverType)
		{
			if (parameters.ServerWriteDuringClientRenegotiation && serverType == ConnectionProviderType.OpenSsl)
				return false;

			return true;
		}

		public static IEnumerable<RenegotiationInstrumentParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			return GetInstrumentationTypes (ctx, category).Select (t => Create (ctx, category, t));
		}

		public static IEnumerable<RenegotiationInstrumentType> GetInstrumentationTypes (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.ClientRenegotiation:
				yield return RenegotiationInstrumentType.RequestClientRenegotiation;
				break;

			case InstrumentationCategory.ServerRenegotiation:
				yield return RenegotiationInstrumentType.RequestRenegotiation;
				yield return RenegotiationInstrumentType.SendBlobBeforeHelloRequest;
				yield return RenegotiationInstrumentType.SendBlobAfterHelloRequest;
				yield return RenegotiationInstrumentType.SendBlobBeforeAndAfterHelloRequest;
				yield return RenegotiationInstrumentType.SendDuplicateHelloRequest;
				yield return RenegotiationInstrumentType.RequestServerRenegotiation;
				yield return RenegotiationInstrumentType.RequestServerRenegotiationWithPendingRead;
				break;

			case InstrumentationCategory.Renegotiation:
				yield return RenegotiationInstrumentType.SendBlobBeforeRenegotiatingHello;
				yield return RenegotiationInstrumentType.SendBlobBeforeRenegotiatingHelloNoPendingRead;
				yield return RenegotiationInstrumentType.RequestClientRenegotiationWithPendingWrite;
				break;

			case InstrumentationCategory.MartinTest:
			case InstrumentationCategory.MartinTestClient:
			case InstrumentationCategory.MartinTestServer:
				yield return RenegotiationInstrumentType.MartinTest;
				break;

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				break;
			}
		}

		static RenegotiationInstrumentParameters CreateParameters (InstrumentationCategory category, RenegotiationInstrumentType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new RenegotiationInstrumentParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		static RenegotiationInstrumentParameters Create (TestContext ctx, InstrumentationCategory category, RenegotiationInstrumentType type)
		{
			var parameters = CreateParameters (category, type);

			switch (type) {
			case RenegotiationInstrumentType.RequestRenegotiation:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation
				};
				break;

			case RenegotiationInstrumentType.SendBlobBeforeHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendBlobBeforeHelloRequest
				};
				break;

			case RenegotiationInstrumentType.SendBlobAfterHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendBlobAfterHelloRequest
				};
				break;

			case RenegotiationInstrumentType.SendBlobBeforeAndAfterHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendBlobBeforeHelloRequest,
					HandshakeInstrumentType.SendBlobAfterHelloRequest
				};
				break;

			case RenegotiationInstrumentType.SendDuplicateHelloRequest:
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.RequestServerRenegotiation,
					HandshakeInstrumentType.SendDuplicateHelloRequest
				};
				break;

			case RenegotiationInstrumentType.RequestServerRenegotiation:
				parameters.RequestServerRenegotiation = true;
				break;

			case RenegotiationInstrumentType.RequestServerRenegotiationWithPendingRead:
				parameters.RequestServerRenegotiation = true;
				parameters.QueueServerReadFirst = true;
				break;

			case RenegotiationInstrumentType.SendBlobBeforeRenegotiatingHello:
				parameters.RequestServerRenegotiation = true;
				parameters.QueueServerReadFirst = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello
				};
				break;

			case RenegotiationInstrumentType.SendBlobBeforeRenegotiatingHelloNoPendingRead:
				parameters.RequestServerRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.SendBlobBeforeRenegotiatingHello
				};
				break;

			case RenegotiationInstrumentType.RequestClientRenegotiation:
				parameters.RequestClientRenegotiation = true;
				break;

			case RenegotiationInstrumentType.RequestClientRenegotiationWithPendingWrite:
				parameters.RequestClientRenegotiation = true;
				parameters.ServerWriteDuringClientRenegotiation = true;
				parameters.ServerParameters.UseStreamInstrumentation = true;
				break;

			case RenegotiationInstrumentType.MartinTest:
				parameters.RequestServerRenegotiation = true;
				parameters.HandshakeInstruments = new HandshakeInstrumentType[] {
					HandshakeInstrumentType.AskForClientCertificate
				};
				parameters.EnableDebugging = true;
				break;

			default:
				ctx.AssertFail ("Unsupported connection instrument: '{0}'.", type);
				break;
			}

			return parameters;
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

		protected override void Dispose (bool disposing)
		{
			renegotiationStartedTcs.TrySetCanceled ();
			renegotiationCompletedTcs.TrySetCanceled ();
			base.Dispose (disposing);
		}

		class MyEventSink : InstrumentationEventSink
		{
			public TestContext Context {
				get;
				private set;
			}

			public RenegotiationInstrumentConnectionHandler Handler {
				get;
				private set;
			}

			public MyEventSink (TestContext ctx, RenegotiationInstrumentConnectionHandler handler)
			{
				Context = ctx;
				Handler = handler;
			}

			public void StartRenegotiation (ITlsContext context)
			{
				Handler.OnRenegotiationStarted (Context, context.IsServer);
			}

			public void RenegotiationCompleted (ITlsContext context)
			{
				Handler.OnRenegotiationCompleted (Context, context.IsServer);
			}
		}
	}
}

