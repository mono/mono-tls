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

		public InstrumentationConnectionHandler ConnectionHandler {
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

			ConnectionHandler = CreateConnectionHandler ();
		}

		protected override void InitializeConnection (TestContext ctx)
		{
			ConnectionHandler.InitializeConnection (ctx);
			base.InitializeConnection (ctx);
		}

		protected abstract InstrumentationConnectionHandler CreateConnectionHandler ();

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
			case InstrumentationCategory.ClientRenegotiation:
			case InstrumentationCategory.MartinTestClient:
				return MonoConnectionFlags.ClientInstrumentation;
			case InstrumentationCategory.AllServerSignatureAlgorithms:
			case InstrumentationCategory.ServerSignatureParameters:
			case InstrumentationCategory.ServerConnection:
			case InstrumentationCategory.ServerRenegotiation:
			case InstrumentationCategory.MartinTestServer:
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
			if (Parameters.ExpectClientAlert != null) {
				ctx.Assert (task.IsFaulted, "expecting exception");
				throw new ConnectionFinishedException ();
			}

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

		protected void LogDebug (TestContext ctx, int level, string message, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.AppendFormat ("[{0}]: {1}", GetType ().Name, message);
			if (args.Length > 0)
				sb.Append (" -");
			foreach (var arg in args) {
				sb.Append (" ");
				sb.Append (arg);
			}
			var formatted = sb.ToString ();
			ctx.LogDebug (level, formatted);
		}

		async Task HandleConnection (TestContext ctx, ICommonConnection connection, Task readTask, Task writeTask, CancellationToken cancellationToken)
		{
			var t1 = readTask.ContinueWith (t => {
				LogDebug (ctx, 1, "HandleConnection - read done", connection, t.Status, t.IsFaulted, t.IsCanceled);
				if (t.IsFaulted || t.IsCanceled)
					Dispose ();
			});
			var t2 = writeTask.ContinueWith (t => {
				LogDebug (ctx, 1, "HandleConnection - write done", connection, t.Status, t.IsFaulted, t.IsCanceled);
				if (t.IsFaulted || t.IsCanceled)
					Dispose ();
			});

			LogDebug (ctx, 1, "HandleConnection", connection);

			await Task.WhenAll (readTask, writeTask, t1, t2);
			cancellationToken.ThrowIfCancellationRequested ();

			LogDebug (ctx, 1, "HandleConnection done", connection);
		}

		protected sealed override Task MainLoop (TestContext ctx, CancellationToken cancellationToken)
		{
			return ConnectionHandler.MainLoop (ctx, cancellationToken);
		}

		public override Task<bool> Shutdown (TestContext ctx, CancellationToken cancellationToken)
		{
			ConnectionHandler.OnShutdown (ctx);
			return base.Shutdown (ctx, cancellationToken);
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

