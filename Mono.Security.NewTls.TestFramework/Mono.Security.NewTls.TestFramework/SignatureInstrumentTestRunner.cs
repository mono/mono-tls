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

		public static IEnumerable<SignatureInstrumentParameters> GetParameters (TestContext ctx, InstrumentationTestCategory category)
		{
			switch (category) {
			case InstrumentationTestCategory.ClientSignatureAlgorithms:
				return CreateClientSignatureAlgorithms (ctx);
				
			case InstrumentationTestCategory.ServerSignatureAlgorithms:
				return CreateServerSignatureAlgorithms (ctx);

			case InstrumentationTestCategory.ServerSignatureAlgorithms2:
				return CreateServerSignatureAlgorithms2 (ctx);

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				return null;
			}
		}

		static IEnumerable<SignatureAndHashAlgorithm> GetSignatureAlgorithms ()
		{
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha1, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha224, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha384, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha512, SignatureAlgorithmType.Rsa);
		}

		static IEnumerable<SignatureInstrumentParameters> CreateClientSignatureAlgorithms (TestContext ctx)
		{
			foreach (var algorithm in GetSignatureAlgorithms ()) {
				foreach (var cipher in GetCipherSuites ()) {
					yield return CreateWithClientSignatureAlgorithm (ctx, SignatureInstrumentType.ClientSignatureAlgorithm, algorithm, cipher);
				}
			}
		}

		static IEnumerable<SignatureInstrumentParameters> CreateServerSignatureAlgorithms (TestContext ctx)
		{
			foreach (var algorithm in GetSignatureAlgorithms ()) {
				foreach (var cipher in GetCipherSuites ()) {
					yield return CreateWithServerSignatureAlgorithm (ctx, SignatureInstrumentType.ServerSignatureAlgorithm, algorithm, cipher);
				}
			}
		}

		static IEnumerable<SignatureInstrumentParameters> CreateServerSignatureAlgorithms2 (TestContext ctx)
		{
			yield return Create (ctx, SignatureInstrumentType.ServerChoosesSignatureAlgorithm);
		}

		static IEnumerable<CipherSuiteCode> GetCipherSuites ()
		{
			// Galois-Counter Cipher Suites.
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;

			// Galois-Counter with Legacy RSA Key Exchange.
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384;

			// Diffie-Hellman Cipher Suites
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;

			// Legacy AES Cipher Suites
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
		}

		static SignatureInstrumentParameters CreateParameters (SignatureInstrumentType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new SignatureInstrumentParameters (name, ResourceManager.SelfSignedServerCertificate, type) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ClientCertificate = ResourceManager.MonkeyCertificate, ServerFlags = ServerFlags.RequireClientCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		static SignatureInstrumentParameters CreateWithClientSignatureAlgorithm (TestContext ctx, SignatureInstrumentType type, SignatureAndHashAlgorithm algorithm, CipherSuiteCode cipher)
		{
			var parameters = CreateParameters (type, algorithm.Hash, algorithm.Signature, cipher);

			var signatureParameters = new SignatureParameters ();
			signatureParameters.Add (algorithm);

			switch (type) {
			case SignatureInstrumentType.ClientSignatureAlgorithm:
				parameters.ClientSignatureParameters = signatureParameters;
				parameters.ClientCiphers = new CipherSuiteCode[] { cipher };
				break;

			default:
				ctx.AssertFail ("Unsupported signature instrument: '{0}'.", type);
				break;
			}

			return parameters;
		}

		static SignatureInstrumentParameters CreateWithServerSignatureAlgorithm (TestContext ctx, SignatureInstrumentType type, SignatureAndHashAlgorithm algorithm, CipherSuiteCode cipher)
		{
			var parameters = CreateParameters (type, algorithm.Hash, algorithm.Signature, cipher);

			switch (type) {
			case SignatureInstrumentType.ServerSignatureAlgorithm:
				parameters.ServerSignatureAlgorithm = algorithm;
				parameters.ServerCiphers = new CipherSuiteCode[] { cipher };
				break;

			default:
				ctx.AssertFail ("Unsupported signature instrument: '{0}'.", type);
				break;
			}

			return parameters;
		}

		static SignatureInstrumentParameters Create (TestContext ctx, SignatureInstrumentType type)
		{
			var parameters = CreateParameters (type);

			switch (type) {
			case SignatureInstrumentType.ServerChoosesSignatureAlgorithm:
				break;

			default:
				ctx.AssertFail ("Unsupported signature instrument: '{0}'.", type);
				break;
			}

			return parameters;
		}
	}
}

