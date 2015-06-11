//
// MonoClientAndServerTestRunner.cs
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
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestRunners;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFramework
{
	using TestFeatures;

	public class MonoClientAndServerTestRunner : ClientAndServerTestRunner
	{
		new public MonoClientAndServerParameters Parameters {
			get { return (MonoClientAndServerParameters)base.Parameters; }
		}

		new public IMonoServer Server {
			get { return (IMonoServer)base.Server; }
		}

		new public IMonoClient Client {
			get { return (IMonoClient)base.Client; }
		}

		public MonoClientAndServerTestRunner (IMonoServer server, IMonoClient client, MonoClientAndServerParameters parameters)
			: base (server, client, parameters)
		{
		}

		public static MonoClientAndServerParameters SelectCipherSuite (TestContext ctx, TlsProtocolCode protocol, CipherSuiteCode code)
		{
			var provider = DependencyInjector.Get<ICertificateProvider> ();
			var acceptAll = provider.AcceptAll ();

			string name = string.Format ("select-cipher-{0}-{1}", protocol, code);

			return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = acceptAll
			};
		}

		public static MonoClientAndServerParameters GetParameters (TestContext ctx, MonoClientAndServerTestType type)
		{
			var provider = DependencyInjector.Get<ICertificateProvider> ();
			var acceptAll = provider.AcceptAll ();
			var acceptSelfSigned = provider.AcceptThisCertificate (ResourceManager.SelfSignedServerCertificate);
			var acceptFromCA = provider.AcceptFromCA (ResourceManager.LocalCACertificate);

			var name = type.ToString ();

			switch (type) {
			case MonoClientAndServerTestType.Simple:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll
				};
			case MonoClientAndServerTestType.ValidateCertificate:
				return new MonoClientAndServerParameters (name, ResourceManager.ServerCertificateFromCA) {
					ClientCertificateValidator = acceptFromCA
				};
			case MonoClientAndServerTestType.CheckDefaultCipher:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
				};
			case MonoClientAndServerTestType.SimpleTls10:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ProtocolVersion = ProtocolVersions.Tls10,
					ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA
				};
			case MonoClientAndServerTestType.SimpleTls11:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ProtocolVersion = ProtocolVersions.Tls11,
					ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA
				};
			case MonoClientAndServerTestType.SimpleTls12:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ProtocolVersion = ProtocolVersions.Tls12,
					ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
				};
			case MonoClientAndServerTestType.SelectCiphersTls10:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ProtocolVersion = ProtocolVersions.Tls10,
				};
			case MonoClientAndServerTestType.SelectCiphersTls11:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ProtocolVersion = ProtocolVersions.Tls11
				};
			case MonoClientAndServerTestType.SelectCiphersTls12:
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificateValidator = acceptAll, ProtocolVersion = ProtocolVersions.Tls12
				};

			case MonoClientAndServerTestType.RequestClientCertificate:
				/*
				 * Request client certificate, but do not require it.
				 *
				 * FIXME:
				 * SslStream with Mono's old implementation fails here.
				 */
				return new MonoClientAndServerParameters (name, ResourceManager.SelfSignedServerCertificate) {
					ClientCertificate = ResourceManager.MonkeyCertificate, ClientCertificateValidator = acceptSelfSigned,
					ServerFlags = ServerFlags.AskForClientCertificate, ServerCertificateValidator = acceptFromCA
				};

			default:
				throw new InvalidOperationException ();
			}
		}

		protected override void OnRun (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Parameters.ExpectedCipher != null) {
				ctx.Assert (Client.SupportsConnectionInfo, "client supports connection info");
				ctx.Assert (Server.SupportsConnectionInfo, "server supports connection info");

				var clientInfo = Client.GetConnectionInfo ();
				var serverInfo = Server.GetConnectionInfo ();

				if (ctx.Expect (clientInfo, Is.Not.Null, "client connection info"))
					ctx.Expect (clientInfo.CipherCode, Is.EqualTo (Parameters.ExpectedCipher.Value), "client cipher");
				if (ctx.Expect (serverInfo, Is.Not.Null, "server connection info"))
					ctx.Expect (serverInfo.CipherCode, Is.EqualTo (Parameters.ExpectedCipher.Value), "server cipher");
			}

			if (Parameters.ProtocolVersion != null) {
				ctx.Expect (Client.ProtocolVersion, Is.EqualTo (Parameters.ProtocolVersion), "client protocol version");
				ctx.Expect (Server.ProtocolVersion, Is.EqualTo (Parameters.ProtocolVersion), "server protocol version");
			}

			base.OnRun (ctx, cancellationToken);
		}

		static void ExpectAlert (TestContext ctx, Task t, AlertDescription expectedAlert, string message)
		{
			ctx.Assert (t.IsFaulted, Is.True, "#1:" + message);
			var baseException = t.Exception.GetBaseException ();
			if (baseException is AggregateException) {
				var aggregate = baseException as AggregateException;
				ctx.Assert (aggregate.InnerExceptions.Count, Is.EqualTo (2), "#2a:" + message);
				var authExcType = aggregate.InnerExceptions [0].GetType ();
				ctx.Assert (authExcType.FullName, Is.EqualTo ("System.Security.Authentication.AuthenticationException"), "#2b:" + message);
				baseException = aggregate.InnerExceptions [1];
			}
			ctx.Assert (baseException, Is.InstanceOf<TlsException> (), "#2:" + message);
			var alert = ((TlsException)baseException).Alert;
			ctx.Assert (alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3:" + message);
			ctx.Assert (alert.Description, Is.EqualTo (expectedAlert), "#4:" + message);
		}

		public async Task ExpectAlert (TestContext ctx, AlertDescription alert, CancellationToken cancellationToken)
		{
			var serverTask = Server.WaitForConnection (ctx, cancellationToken);
			var clientTask = Client.WaitForConnection (ctx, cancellationToken);

			var t1 = clientTask.ContinueWith (t => ExpectAlert (ctx, t, alert, "client"));
			var t2 = serverTask.ContinueWith (t => ExpectAlert (ctx, t, alert, "server"));

			await Task.WhenAll (t1, t2);
		}
	}
}

