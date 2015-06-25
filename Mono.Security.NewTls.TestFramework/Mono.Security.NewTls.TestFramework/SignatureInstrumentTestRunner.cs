//
// SignatureInstrumentTestRunner.cs
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
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Resources;

namespace Mono.Security.NewTls.TestFramework
{
	using Instrumentation;

	public class SignatureInstrumentTestRunner : InstrumentationTestRunner
	{
		new public SignatureInstrumentParameters Parameters {
			get { return (SignatureInstrumentParameters)base.Parameters; }
		}

		public SignatureInstrumentTestRunner (IServer server, IClient client, SignatureInstrumentParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
		}

		public override InstrumentCollection CreateInstrument (TestContext ctx)
		{
			var instrumentation = new InstrumentCollection ();
				instrumentation.SignatureInstrument = new SignatureInstrument (ctx, this);
			return instrumentation;
		}

		public static IEnumerable<SignatureInstrumentParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.AllClientSignatureAlgorithms:
				return SelectAlgorithmsAndCiphers (SignatureInstrumentType.ClientSignatureAlgorithmAndCipher).Select (t => Create (ctx, category, t.Item1, t.Item2, t.Item3));

			case InstrumentationCategory.AllServerSignatureAlgorithms:
				return SelectAlgorithmsAndCiphers (SignatureInstrumentType.ServerSignatureAlgorithmAndCipher).Select (t => Create (ctx, category, t.Item1, t.Item2, t.Item3));

			case InstrumentationCategory.ClientSignatureParameters:
				return ClientSignatureParameterTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.ServerSignatureParameters:
				return ServerSignatureParameterTypes.Select (t => Create (ctx, category, t));

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				return null;
			}
		}

		internal static readonly SignatureAndHashAlgorithm[] AllSignatureAlgorithms = {
			new SignatureAndHashAlgorithm (HashAlgorithmType.Sha1, SignatureAlgorithmType.Rsa),
			new SignatureAndHashAlgorithm (HashAlgorithmType.Sha224, SignatureAlgorithmType.Rsa),
			new SignatureAndHashAlgorithm (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa),
			new SignatureAndHashAlgorithm (HashAlgorithmType.Sha384, SignatureAlgorithmType.Rsa),
			new SignatureAndHashAlgorithm (HashAlgorithmType.Sha512, SignatureAlgorithmType.Rsa),
		};

		internal static readonly CipherSuiteCode[] AllCipherSuites = {
			// Galois-Counter Cipher Suites.
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,

			// Galois-Counter with Legacy RSA Key Exchange.
			CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384,

			// Diffie-Hellman Cipher Suites
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,

			// Legacy AES Cipher Suites
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
		};

		static IEnumerable<Tuple<SignatureAndHashAlgorithm,CipherSuiteCode>> SelectAlgorithmsAndCiphers ()
		{
			return Enumerable.Zip (AllSignatureAlgorithms, AllCipherSuites, (a, c) => Tuple.Create (a, c));
		}

		static IEnumerable<Tuple<SignatureInstrumentType,SignatureAndHashAlgorithm,CipherSuiteCode>> SelectAlgorithmsAndCiphers (params SignatureInstrumentType[] types)
		{
			return Enumerable.Zip (types, SelectAlgorithmsAndCiphers (), (first, second) => Tuple.Create (first, second.Item1, second.Item2));
		}

		internal static readonly SignatureInstrumentType[] ClientSignatureParameterTypes = {
			// SignatureInstrumentType.VerifyClientSignatureAlgorithms,
			// SignatureInstrumentType.ClientProvidesSomeUnsupportedSignatureAlgorithms,
			SignatureInstrumentType.ClientProvidesNoSupportedSignatureAlgorithms
		};

		internal static readonly SignatureInstrumentType[] ServerSignatureParameterTypes = {
		};

		static SignatureInstrumentParameters CreateParameters (InstrumentationCategory category, SignatureInstrumentType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new SignatureInstrumentParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ClientCertificate = ResourceManager.MonkeyCertificate, ServerFlags = ServerFlags.RequireClientCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		static SignatureInstrumentParameters Create (
			TestContext ctx, InstrumentationCategory category, SignatureInstrumentType type,
			SignatureAndHashAlgorithm algorithm, CipherSuiteCode cipher)
		{
			var parameters = CreateParameters (category, type, algorithm.Hash, algorithm.Signature, cipher);

			var signatureParameters = new SignatureParameters ();
			signatureParameters.Add (algorithm);

			switch (type) {
			case SignatureInstrumentType.ClientSignatureAlgorithmAndCipher:
				parameters.ClientSignatureParameters = signatureParameters;
				parameters.ClientCiphers = new CipherSuiteCode[] { cipher };
				break;

			case SignatureInstrumentType.ServerSignatureAlgorithmAndCipher:
				parameters.ServerSignatureAlgorithm = algorithm;
				parameters.ServerCiphers = new CipherSuiteCode[] { cipher };
				break;

			default:
				ctx.AssertFail ("Unsupported signature instrument: '{0}'.", type);
				break;
			}

			return parameters;
		}

		static SignatureInstrumentParameters Create (TestContext ctx, InstrumentationCategory category, SignatureInstrumentType type)
		{
			var parameters = CreateParameters (category, type);

			switch (type) {
			case SignatureInstrumentType.VerifyClientSignatureAlgorithms:
				parameters.ExpectClientAlert = AlertDescription.IlegalParameter;
				parameters.ServerFlags |= ServerFlags.ClientAbortsHandshake;
				goto case SignatureInstrumentType.ClientProvidesSomeUnsupportedSignatureAlgorithms;

			case SignatureInstrumentType.ClientProvidesSomeUnsupportedSignatureAlgorithms:
				parameters.ClientSignatureParameters = new SignatureParameters ();
				parameters.ClientSignatureParameters.Add (HashAlgorithmType.Sha1, SignatureAlgorithmType.Dsa);
				parameters.ClientSignatureParameters.Add (HashAlgorithmType.Unknown, SignatureAlgorithmType.Unknown);
				parameters.ClientSignatureParameters.Add (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa);
				break;

			case SignatureInstrumentType.ClientProvidesNoSupportedSignatureAlgorithms:
				parameters.ClientSignatureParameters = new SignatureParameters ();
				parameters.ClientSignatureParameters.Add (HashAlgorithmType.Unknown, SignatureAlgorithmType.Dsa);
				parameters.ExpectServerAlert = AlertDescription.IlegalParameter;
				parameters.ClientCertificate = null;
				parameters.ServerFlags = ServerFlags.None;
				break;

			default:
				ctx.AssertFail ("Unsupported signature instrument: '{0}'.", type);
				break;
			}

			return parameters;
		}
	}
}

