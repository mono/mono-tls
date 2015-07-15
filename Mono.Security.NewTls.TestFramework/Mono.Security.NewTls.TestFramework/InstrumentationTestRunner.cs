//
// InstrumentationTestRunner.cs
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
using System.Net;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.HttpFramework;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.TestRunners;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class InstrumentationTestRunner : ClientAndServerTestRunner, InstrumentationProvider
	{
		new public InstrumentationParameters Parameters {
			get { return (InstrumentationParameters)base.Parameters; }
		}

		public InstrumentationCategory Category {
			get { return Parameters.Category; }
		}

		public MonoConnectionFlags ConnectionFlags {
			get;
			private set;
		}

		public InstrumentationTestRunner (IServer server, IClient client, InstrumentationParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters)
		{
			ConnectionFlags = flags;

			if ((flags & MonoConnectionFlags.ServerInstrumentation) != 0)
				((IMonoServer)server).InstrumentationProvider = this;
			if ((flags & MonoConnectionFlags.ClientInstrumentation) != 0)
				((IMonoClient)client).InstrumentationProvider = this;
		}

		public abstract Instrumentation CreateInstrument (TestContext ctx);

		public static MonoConnectionFlags GetConnectionFlags (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.SimpleMonoClient:
			case InstrumentationCategory.SelectClientCipher:
				return MonoConnectionFlags.RequireMonoClient;
			case InstrumentationCategory.SimpleMonoServer:
			case InstrumentationCategory.SelectServerCipher:
				return MonoConnectionFlags.RequireMonoServer;
			case InstrumentationCategory.SimpleMonoConnection:
			case InstrumentationCategory.MonoProtocolVersions:
			case InstrumentationCategory.SelectCipher:
				return MonoConnectionFlags.RequireMonoClient | MonoConnectionFlags.RequireMonoServer;
			case InstrumentationCategory.AllClientSignatureAlgorithms:
			case InstrumentationCategory.ClientSignatureParameters:
			case InstrumentationCategory.ClientConnection:
				return MonoConnectionFlags.ClientInstrumentation;
			case InstrumentationCategory.AllServerSignatureAlgorithms:
			case InstrumentationCategory.ServerSignatureParameters:
			case InstrumentationCategory.ServerConnection:
			case InstrumentationCategory.ServerRenegotiation:
				return MonoConnectionFlags.ServerInstrumentation;
			case InstrumentationCategory.SignatureAlgorithms:
			case InstrumentationCategory.Connection:
			case InstrumentationCategory.Renegotiation:
				return MonoConnectionFlags.ClientInstrumentation | MonoConnectionFlags.ServerInstrumentation;
			case InstrumentationCategory.MartinTest:
				return MonoConnectionFlags.ServerInstrumentation | MonoConnectionFlags.ClientInstrumentation;
			case InstrumentationCategory.ManualClient:
				return MonoConnectionFlags.ServerInstrumentation;
			case InstrumentationCategory.ManualServer:
				return MonoConnectionFlags.ClientInstrumentation;
			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				return MonoConnectionFlags.None;
			}
		}

		public static bool IsClientSupported (TestContext ctx, InstrumentationCategory category, ConnectionProviderType type)
		{
			var connectionFlags = GetConnectionFlags (ctx, category);
			switch (type) {
			case ConnectionProviderType.NewTLS:
				return (connectionFlags & (MonoConnectionFlags.ClientInstrumentation | MonoConnectionFlags.RequireMonoClient)) == 0;
			case ConnectionProviderType.OpenSsl:
				return (connectionFlags & (MonoConnectionFlags.ClientInstrumentation)) == 0;
			case ConnectionProviderType.MonoWithNewTLS:
				return true;
			default:
				return false;
			}
		}

		public static bool IsServerSupported (TestContext ctx, InstrumentationCategory category, ConnectionProviderType type)
		{
			var connectionFlags = GetConnectionFlags (ctx, category);
			switch (type) {
			case ConnectionProviderType.NewTLS:
				return (connectionFlags & (MonoConnectionFlags.ServerInstrumentation | MonoConnectionFlags.RequireMonoServer)) == 0;
			case ConnectionProviderType.OpenSsl:
				return (connectionFlags & (MonoConnectionFlags.ServerInstrumentation)) == 0;
			case ConnectionProviderType.MonoWithNewTLS:
				return true;
			default:
				return false;
			}
		}

		public bool IsManualConnection {
			get {
				if (Category == InstrumentationCategory.ManualClient || Category == InstrumentationCategory.ManualServer)
					return true;
				return (ConnectionFlags & (MonoConnectionFlags.ManualClient | MonoConnectionFlags.ManualServer)) != 0;
			}
		}

		public static IEnumerable<R> Join<T,U,R> (IEnumerable<T> first, IEnumerable<U> second, Func<T, U, R> resultSelector) {
			foreach (var e1 in first) {
				foreach (var e2 in second) {
					yield return resultSelector (e1, e2);
				}
			}
		}

		protected static ICertificateValidator AcceptAnyCertificate {
			get { return DependencyInjector.Get<ICertificateProvider> ().AcceptAll (); }
		}

		protected override void OnWaitForClientConnectionCompleted (TestContext ctx, Task task)
		{
			if (Parameters.ExpectClientAlert != null) {
				MonoConnectionHelper.ExpectAlert (ctx, task, Parameters.ExpectClientAlert.Value, "expect client alert");
				throw new ConnectionFinishedException ();
			}

			base.OnWaitForClientConnectionCompleted (ctx, task);
		}

		protected override void OnWaitForServerConnectionCompleted (TestContext ctx, Task task)
		{
			if (Parameters.ExpectServerAlert != null) {
				MonoConnectionHelper.ExpectAlert (ctx, task, Parameters.ExpectServerAlert.Value, "expect server alert");
				throw new ConnectionFinishedException ();
			}

			base.OnWaitForServerConnectionCompleted (ctx, task);
		}

		protected void CheckCipher (TestContext ctx, IMonoCommonConnection connection, CipherSuiteCode cipher)
		{
			ctx.Assert (connection.SupportsConnectionInfo, "supports connection info");
			var connectionInfo = connection.GetConnectionInfo ();

			if (ctx.Expect (connectionInfo, Is.Not.Null, "connection info"))
				ctx.Expect (connectionInfo.CipherCode, Is.EqualTo (cipher), "expected cipher");
		}

		protected override Task OnRun (TestContext ctx, CancellationToken cancellationToken)
		{
			var monoClient = Client as IMonoClient;
			var monoServer = Server as IMonoServer;

			if (monoClient != null) {
				var expectedCipher = Parameters.ExpectedClientCipher ?? Parameters.ExpectedCipher;
				if (expectedCipher != null)
					CheckCipher (ctx, monoClient, expectedCipher.Value);
			}

			if (monoServer != null) {
				var expectedCipher = Parameters.ExpectedServerCipher ?? Parameters.ExpectedCipher;
				if (expectedCipher != null)
					CheckCipher (ctx, monoServer, expectedCipher.Value);
			}

			if (!IsManualConnection && Parameters.ProtocolVersion != null) {
				ctx.Expect (Client.ProtocolVersion, Is.EqualTo (Parameters.ProtocolVersion), "client protocol version");
				ctx.Expect (Server.ProtocolVersion, Is.EqualTo (Parameters.ProtocolVersion), "server protocol version");
			}

			if (Server.Provider.SupportsSslStreams && (Parameters.ServerFlags & ServerFlags.RequireClientCertificate) != 0) {
				ctx.Expect (Server.SslStream.HasRemoteCertificate, "has remote certificate");
				ctx.Expect (Server.SslStream.IsMutuallyAuthenticated, "is mutually authenticated");
			}

			return base.OnRun (ctx, cancellationToken);
		}

		protected override Task MainLoop (TestContext ctx, CancellationToken cancellationToken)
		{
			if ((ConnectionFlags & MonoConnectionFlags.ManualServer) != 0)
				return RunWithManualServer (ctx, cancellationToken);
			if ((ConnectionFlags & MonoConnectionFlags.ManualClient) != 0)
				return RunWithManualClient (ctx, cancellationToken);

			return base.MainLoop (ctx, cancellationToken);
		}

		async Task RunWithManualServer (TestContext ctx, CancellationToken cancellationToken)
		{
			var clientStream = new StreamWrapper (Client.Stream);

			ctx.LogMessage ("WRITING REQUEST: {0}", Parameters.ClientParameters.TargetHost ?? "<null>");

			await clientStream.WriteLineAsync ("GET / HTTP/1.0");
			try {
				if (Parameters.ClientParameters.TargetHost != null)
					await clientStream.WriteLineAsync (string.Format ("Host: {0}", Parameters.ClientParameters.TargetHost));
				await clientStream.WriteLineAsync ();
			} catch (Exception ex) {
				ctx.LogMessage ("RECEIVED EXCEPTION WHILE WRITING REQUEST: {0}", ex.Message);
			}

			var line = await clientStream.ReadLineAsync ();
			ctx.LogMessage ("GOT RESPONSE: {0}", line);

			HttpProtocol protocol;
			HttpStatusCode status;
			if (!HttpResponse.ParseResponseHeader (line, out protocol, out status))
				throw new ConnectionException ("Got unexpected output from server: '{0}'", line);

			ctx.LogMessage ("GOT RESPONSE: {0} {1}", protocol, status);

			await Shutdown (ctx, SupportsCleanShutdown, cancellationToken);
		}

		async Task RunWithManualClient (TestContext ctx, CancellationToken cancellationToken)
		{
			ctx.LogMessage ("MANUAL CLIENT");

			var serverStream = new StreamWrapper (Server.Stream);
			await serverStream.WriteLineAsync ("Hello World!");

			ctx.LogMessage ("WAITING FOR CLIENT INPUT");

			var line = await serverStream.ReadLineAsync ();
			ctx.LogMessage ("GOT CLIENT MESSAGE: {0}", line);

			await Shutdown (ctx, SupportsCleanShutdown, cancellationToken);
		}

		public async Task ExpectAlert (TestContext ctx, AlertDescription alert, CancellationToken cancellationToken)
		{
			var serverTask = Server.WaitForConnection (ctx, cancellationToken);
			var clientTask = Client.WaitForConnection (ctx, cancellationToken);

			var t1 = clientTask.ContinueWith (t => MonoConnectionHelper.ExpectAlert (ctx, t, alert, "client"));
			var t2 = serverTask.ContinueWith (t => MonoConnectionHelper.ExpectAlert (ctx, t, alert, "server"));

			await Task.WhenAll (t1, t2);
		}
	}
}

