//
// GenericConnectionInstrumentTestRunner.cs
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
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public class GenericConnectionInstrumentTestRunner : ConnectionInstrumentTestRunner
	{
		public GenericConnectionInstrumentTestRunner (IServer server, IClient client, GenericConnectionInstrumentParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
		}

		protected override InstrumentationConnectionHandler CreateConnectionHandler ()
		{
			return new ConnectionInstrumentConnectionHandler (this);
		}

		public static bool IsSupported (GenericConnectionInstrumentParameters parameters, ConnectionProviderType clientType, ConnectionProviderType serverType)
		{
			return true;
		}

		public static IEnumerable<GenericConnectionInstrumentParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			return GetInstrumentationTypes (ctx, category).Select (t => Create (ctx, category, t));
		}

		public static IEnumerable<GenericConnectionInstrumentType> GetInstrumentationTypes (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.ClientConnection:
				yield return GenericConnectionInstrumentType.FragmentHandshakeMessages;
				yield return GenericConnectionInstrumentType.SendBlobAfterReceivingFinish;
				yield return GenericConnectionInstrumentType.InvalidClientCertificateV1;
				break;

			case InstrumentationCategory.ServerConnection:
				yield return GenericConnectionInstrumentType.FragmentHandshakeMessages;
				yield return GenericConnectionInstrumentType.InvalidServerCertificateV1;
				yield return GenericConnectionInstrumentType.InvalidServerCertificateRsa512;
				break;

			case InstrumentationCategory.Connection:
				yield return GenericConnectionInstrumentType.FragmentHandshakeMessages;
				yield return GenericConnectionInstrumentType.ServerProvidesInvalidCertificate;
				yield return GenericConnectionInstrumentType.ClientProvidesInvalidCertificate;
				yield return GenericConnectionInstrumentType.RequireRsaKeyExchange;
				yield return GenericConnectionInstrumentType.RsaKeyExchangeNotAllowed;
				yield return GenericConnectionInstrumentType.RequireDheKeyExchange;
				yield return GenericConnectionInstrumentType.DheKeyExchangeNotAllowed;
				break;

			case InstrumentationCategory.CertificateChecks:
				yield return GenericConnectionInstrumentType.InvalidServerCertificateV1;
				yield return GenericConnectionInstrumentType.InvalidServerCertificateRsa512;
				yield return GenericConnectionInstrumentType.InvalidClientCertificateV1;
				yield return GenericConnectionInstrumentType.InvalidServerCertificateRsa512;
				yield return GenericConnectionInstrumentType.ServerProvidesInvalidCertificate;
				yield return GenericConnectionInstrumentType.ClientProvidesInvalidCertificate;
				yield return GenericConnectionInstrumentType.RequireRsaKeyExchange;
				yield return GenericConnectionInstrumentType.RsaKeyExchangeNotAllowed;
				yield return GenericConnectionInstrumentType.RequireDheKeyExchange;
				yield return GenericConnectionInstrumentType.DheKeyExchangeNotAllowed;
				break;

			case InstrumentationCategory.ManualClient:
				yield return GenericConnectionInstrumentType.MartinClientPuppy;
				break;

			case InstrumentationCategory.ManualServer:
				yield return GenericConnectionInstrumentType.MartinServerPuppy;
				break;

			case InstrumentationCategory.MartinTest:
				yield return GenericConnectionInstrumentType.MartinTest;
				break;

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				break;
			}
		}

		static GenericConnectionInstrumentParameters CreateParameters (InstrumentationCategory category, GenericConnectionInstrumentType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new GenericConnectionInstrumentParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		protected static ICertificateValidator AcceptFromLocalCA {
			get { return DependencyInjector.Get<ICertificateProvider> ().AcceptFromCA (ResourceManager.LocalCACertificate); }
		}

		protected static ICertificateValidator AcceptSelfSigned {
			get { return DependencyInjector.Get<ICertificateProvider> ().AcceptThisCertificate (ResourceManager.SelfSignedServerCertificate); }
		}

		static GenericConnectionInstrumentParameters Create (TestContext ctx, InstrumentationCategory category, GenericConnectionInstrumentType type)
		{
			var parameters = CreateParameters (category, type);

			switch (type) {
			case GenericConnectionInstrumentType.FragmentHandshakeMessages:
				parameters.Add (HandshakeInstrumentType.FragmentHandshakeMessages);
				break;

			case GenericConnectionInstrumentType.SendBlobAfterReceivingFinish:
				parameters.Add (HandshakeInstrumentType.SendBlobAfterReceivingFinish);
				break;

			case GenericConnectionInstrumentType.InvalidServerCertificateV1:
				parameters.ServerParameters.ServerCertificate = ResourceManager.InvalidServerCertificateV1;
				parameters.ExpectServerAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.InvalidServerCertificateRsa512:
				parameters.ServerParameters.ServerCertificate = ResourceManager.InvalidServerCertificateRsa512;
				parameters.ExpectServerAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.ServerProvidesInvalidCertificate:
				parameters.ServerParameters.ServerCertificate = ResourceManager.InvalidServerCertificateV1;
				parameters.Add (HandshakeInstrumentType.OverrideServerCertificateSelection);
				parameters.ExpectClientAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.InvalidClientCertificateV1:
				parameters.ClientCertificate = ResourceManager.InvalidClientCertificateV1;
				parameters.ServerFlags |= ServerFlags.RequireClientCertificate;
				parameters.ExpectClientAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.InvalidClientCertificateRsa512:
				parameters.ClientCertificate = ResourceManager.InvalidClientCertificateRsa512;
				parameters.ServerFlags |= ServerFlags.RequireClientCertificate;
				parameters.ExpectClientAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.ClientProvidesInvalidCertificate:
				parameters.ClientCertificate = ResourceManager.InvalidClientCertificateV1;
				parameters.ServerFlags |= ServerFlags.RequireClientCertificate;
				parameters.Add (HandshakeInstrumentType.OverrideClientCertificateSelection);
				parameters.ExpectServerAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.RequireRsaKeyExchange:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateRsaOnly;
				parameters.ClientCiphers = new CipherSuiteCode[] {
					CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
				};
				parameters.ExpectedServerCipher = CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
				break;

			case GenericConnectionInstrumentType.RsaKeyExchangeNotAllowed:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateDheOnly;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA };
				parameters.ExpectServerAlert = AlertDescription.InsuficientSecurity;
				break;

			case GenericConnectionInstrumentType.RequireDheKeyExchange:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateDheOnly;
				parameters.ClientCiphers = new CipherSuiteCode[] {
					CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA, CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
				};
				parameters.ExpectedServerCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
				break;

			case GenericConnectionInstrumentType.DheKeyExchangeNotAllowed:
				parameters.ProtocolVersion = ProtocolVersions.Tls12;
				parameters.ServerParameters.ServerCertificate = ResourceManager.ServerCertificateRsaOnly;
				parameters.ServerCiphers = new CipherSuiteCode[] { CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA };
				parameters.ExpectServerAlert = AlertDescription.InsuficientSecurity;
				break;

			case GenericConnectionInstrumentType.MartinClientPuppy:
			case GenericConnectionInstrumentType.MartinServerPuppy:
				parameters.ServerFlags |= ServerFlags.RequireClientCertificate;
				parameters.ClientCertificateValidator = AcceptSelfSigned;
				parameters.ServerCertificateValidator = AcceptFromLocalCA;
				break;

			case GenericConnectionInstrumentType.MartinTest:
				goto case GenericConnectionInstrumentType.ClientProvidesInvalidCertificate;

			default:
				ctx.AssertFail ("Unsupported connection instrument: '{0}'.", type);
				break;
			}

			if (parameters.ExpectClientAlert != null || parameters.ExpectServerAlert != null)
				parameters.Add (HandshakeInstrumentType.DontSendAlerts);

			return parameters;
		}
	}
}

