//
// SimpleConnectionTestRunner.cs
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
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestRunners;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFramework
{
	public class SimpleConnectionTestRunner : InstrumentationTestRunner
	{
		new public SimpleConnectionParameters Parameters {
			get { return (SimpleConnectionParameters)base.Parameters; }
		}

		public SimpleConnectionType Type {
			get { return Parameters.Type; }
		}

		public SimpleConnectionTestRunner (IServer server, IClient client, SimpleConnectionParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
		}

		public override Instrumentation CreateInstrument (TestContext ctx)
		{
			return null;
		}

		public static IEnumerable<SimpleConnectionParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.SimpleMonoClient:
				return ClientConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.SimpleMonoServer:
				return ServerConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.SimpleMonoConnection:
				return ConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.MonoProtocolVersions:
				return AllVersionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.MartinTest:
				return MartinTestTypes.Select (t => Create (ctx, category, t));

			default:
				ctx.AssertFail ("Unsupported connection category: '{0}'.", category);
				return null;
			}
		}

		internal static readonly SimpleConnectionType[] ClientConnectionTypes = {
			SimpleConnectionType.CheckDefaultCipher,
			SimpleConnectionType.SimpleTls10,
			SimpleConnectionType.SimpleTls11,
			SimpleConnectionType.SimpleTls12
		};

		internal static readonly SimpleConnectionType[] ServerConnectionTypes = {
			SimpleConnectionType.CheckDefaultCipher,
			SimpleConnectionType.SimpleTls10,
			SimpleConnectionType.SimpleTls11,
			SimpleConnectionType.SimpleTls12
		};

		internal static readonly SimpleConnectionType[] ConnectionTypes = {
			SimpleConnectionType.CheckDefaultCipher,
			SimpleConnectionType.SimpleTls10,
			SimpleConnectionType.SimpleTls11,
			SimpleConnectionType.SimpleTls12
		};

		internal static readonly SimpleConnectionType[] AllVersionTypes = {
			SimpleConnectionType.Simple,
			SimpleConnectionType.ValidateCertificate,
			SimpleConnectionType.RequestClientCertificate,
			SimpleConnectionType.RequireClientCertificateRSA,
			SimpleConnectionType.RequireClientCertificateDHE
		};

		internal static readonly SimpleConnectionType[] MartinTestTypes = {
			SimpleConnectionType.MartinTest
		};

		static SimpleConnectionParameters CreateParameters (InstrumentationCategory category, SimpleConnectionType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new SimpleConnectionParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate
			};
		}

		static SimpleConnectionParameters Create (TestContext ctx, InstrumentationCategory category, SimpleConnectionType type)
		{
			var parameters = CreateParameters (category, type);

			var provider = DependencyInjector.Get<ICertificateProvider> ();
			var acceptSelfSigned = provider.AcceptThisCertificate (ResourceManager.SelfSignedServerCertificate);
			var acceptFromCA = provider.AcceptFromCA (ResourceManager.LocalCACertificate);

			switch (type) {
			case SimpleConnectionType.Simple:
				break;

			case SimpleConnectionType.ValidateCertificate:
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateFromCA;
				parameters.ClientCertificateValidator = acceptFromCA;
				break;

			case SimpleConnectionType.CheckDefaultCipher:
				parameters.ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
				break;

			case SimpleConnectionType.SimpleTls10:
				parameters.ProtocolVersion = ProtocolVersions.Tls10;
				parameters.ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
				break;

			case SimpleConnectionType.SimpleTls11:
				parameters.ProtocolVersion = ProtocolVersions.Tls11;
				parameters.ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
				break;

			case SimpleConnectionType.SimpleTls12:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
				break;

			case SimpleConnectionType.SelectCiphersTls10:
				parameters.ProtocolVersion = ProtocolVersions.Tls10;
				break;

			case SimpleConnectionType.SelectCiphersTls11:
				parameters.ProtocolVersion = ProtocolVersions.Tls11;
				break;

			case SimpleConnectionType.SelectCiphersTls12:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				break;

			case SimpleConnectionType.RequestClientCertificate:
				/*
				 * Request client certificate, but do not require it.
				 *
				 * FIXME:
				 * SslStream with Mono's old implementation fails here.
				 */
				parameters.ClientCertificate = ResourceManager.MonkeyCertificate;
				parameters.ClientCertificateValidator = acceptSelfSigned;
				parameters.ServerFlags = ServerFlags.AskForClientCertificate;
				parameters.ServerCertificateValidator = acceptFromCA;
				break;

			case SimpleConnectionType.RequireClientCertificateRSA:
				/*
				 * Require client certificate.
				 *
				 */
				parameters.ClientCertificate = ResourceManager.MonkeyCertificate;
				parameters.ClientCertificateValidator = acceptSelfSigned;
				parameters.ServerFlags = ServerFlags.RequireClientCertificate;
				parameters.ServerCertificateValidator = acceptFromCA;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA };
				break;

			case SimpleConnectionType.RequireClientCertificateDHE:
				/*
				 * Require client certificate.
				 *
				 */
				parameters.ClientCertificate = ResourceManager.MonkeyCertificate;
				parameters.ClientCertificateValidator = acceptSelfSigned;
				parameters.ServerFlags = ServerFlags.RequireClientCertificate;
				parameters.ServerCertificateValidator = acceptFromCA;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA };
				break;

			case SimpleConnectionType.MartinTest:
				break;

			default:
				ctx.AssertFail ("Unsupported connection type: '{0}'.", type);
				break;
			}

			return parameters;
		}

		void CheckCipher (TestContext ctx, IMonoCommonConnection connection, CipherSuiteCode cipher)
		{
			ctx.Assert (connection.SupportsConnectionInfo, "supports connection info");
			var connectionInfo = connection.GetConnectionInfo ();

			if (ctx.Expect (connectionInfo, Is.Not.Null, "connection info"))
				ctx.Expect (connectionInfo.CipherCode, Is.EqualTo (cipher), "expected cipher");
		}

		protected override void OnRun (TestContext ctx, CancellationToken cancellationToken)
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

			if (Parameters.ProtocolVersion != null) {
				ctx.Expect (Client.ProtocolVersion, Is.EqualTo (Parameters.ProtocolVersion), "client protocol version");
				ctx.Expect (Server.ProtocolVersion, Is.EqualTo (Parameters.ProtocolVersion), "server protocol version");
			}

			if (Server.Provider.SupportsSslStreams && (Parameters.ServerFlags & ServerFlags.RequireClientCertificate) != 0) {
				ctx.Expect (Server.SslStream.HasRemoteCertificate, "has remote certificate");
				ctx.Expect (Server.SslStream.IsMutuallyAuthenticated, "is mutually authenticated");
			}

			base.OnRun (ctx, cancellationToken);
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

