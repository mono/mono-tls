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

		protected override InstrumentationConnectionHandler CreateConnectionHandler ()
		{
			return new DefaultInstrumentationConnectionHandler (this);
		}

		public override Instrumentation CreateInstrument (TestContext ctx)
		{
			return null;
		}

		public static IEnumerable<SimpleConnectionType> GetTestTypes (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.SimpleMonoClient:
				yield return SimpleConnectionType.CheckDefaultCipher;
				yield return SimpleConnectionType.SimpleTls10;
				yield return SimpleConnectionType.SimpleTls11;
				yield return SimpleConnectionType.SimpleTls12;
				yield break;

			case InstrumentationCategory.SimpleMonoServer:
				yield return SimpleConnectionType.CheckDefaultCipher;
				yield return SimpleConnectionType.SimpleTls10;
				yield return SimpleConnectionType.SimpleTls11;
				yield return SimpleConnectionType.SimpleTls12;
				yield break;

			case InstrumentationCategory.SimpleMonoConnection:
				yield return SimpleConnectionType.CheckDefaultCipher;
				yield return SimpleConnectionType.SimpleTls10;
				yield return SimpleConnectionType.SimpleTls11;
				yield return SimpleConnectionType.SimpleTls12;
				yield break;

			case InstrumentationCategory.MonoProtocolVersions:
				yield return SimpleConnectionType.Simple;
				yield return SimpleConnectionType.ValidateCertificate;
				yield return SimpleConnectionType.RequestClientCertificate;
				yield return SimpleConnectionType.RequireClientCertificateRSA;
				yield return SimpleConnectionType.RequireClientCertificateDHE;
				yield break;

			case InstrumentationCategory.InvalidCertificates:
				yield return SimpleConnectionType.CipherSelectionOrder;
				yield return SimpleConnectionType.CipherSelectionOrder2;
				yield return SimpleConnectionType.InvalidServerCertificate;
				yield return SimpleConnectionType.RequireRsaKeyExchange;
				yield return SimpleConnectionType.RsaKeyExchangeNotAllowed;
				yield return SimpleConnectionType.RequireDheKeyExchange;
				yield return SimpleConnectionType.DheKeyExchangeNotAllowed;
				yield break;

			case InstrumentationCategory.MartinTest:
			case InstrumentationCategory.ManualClient:
			case InstrumentationCategory.ManualServer:
				yield return SimpleConnectionType.MartinTest;
				yield break;

			default:
				ctx.AssertFail ("Unspported connection category: '{0}.", category);
				yield break;
			}
		}

		public static IEnumerable<SimpleConnectionParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			return GetTestTypes (ctx, category).Select (t => Create (ctx, category, t));
		}

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

			case SimpleConnectionType.CipherSelectionOrder:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ClientCiphers = new CipherSuiteCode[] {
					CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
				};
				parameters.ExpectedServerCipher = CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
				break;

			case SimpleConnectionType.CipherSelectionOrder2:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ClientCiphers = new CipherSuiteCode[] {
					CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
				};
				parameters.ExpectedServerCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
				break;

			case SimpleConnectionType.InvalidServerCertificate:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.InvalidServerCertificate;
				parameters.ExpectServerAlert = AlertDescription.UnsupportedCertificate;
				break;

			case SimpleConnectionType.RequireRsaKeyExchange:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateRsaOnly;
				parameters.ClientCiphers = new CipherSuiteCode[] {
					CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
				};
				parameters.ExpectedServerCipher = CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
				break;

			case SimpleConnectionType.RsaKeyExchangeNotAllowed:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateDheOnly;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA };
				parameters.ExpectServerAlert = AlertDescription.InsuficientSecurity;
				break;

			case SimpleConnectionType.RequireDheKeyExchange:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateDheOnly;
				parameters.ClientCiphers = new CipherSuiteCode[] {
					CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
				};
				parameters.ExpectedServerCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
				break;

			case SimpleConnectionType.DheKeyExchangeNotAllowed:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateRsaOnly;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA };
				parameters.ExpectServerAlert = AlertDescription.InsuficientSecurity;
				break;

			case SimpleConnectionType.MartinTest:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateRsaOnly;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA };
				parameters.ExpectServerAlert = AlertDescription.InsuficientSecurity;
				break;

			default:
				ctx.AssertFail ("Unsupported connection type: '{0}'.", type);
				break;
			}

			return parameters;
		}
	}
}

