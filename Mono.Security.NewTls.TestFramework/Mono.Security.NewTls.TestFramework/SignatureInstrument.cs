//
// SignatureInstrument.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.TestFramework
{
	public class SignatureInstrument : SignatureProvider
	{
		public TestContext Context {
			get;
			private set;
		}

		public SignatureInstrumentTestRunner TestRunner {
			get;
			private set;
		}

		public SignatureInstrumentParameters Parameters {
			get { return TestRunner.Parameters; }
		}

		public SignatureInstrument (TestContext ctx, SignatureInstrumentTestRunner runner)
		{
			Context = ctx;
			TestRunner = runner;
		}

		public override SignatureParameters GetClientSignatureParameters (ITlsContext ctx)
		{
			if (ctx.IsServer)
				throw new InvalidOperationException ();

			if (Parameters.Type == SignatureInstrumentType.NoClientSignatureAlgorithms)
				return null;

			var parameters = Parameters.ClientSignatureParameters;
			if (parameters == null)
				return base.GetClientSignatureParameters (ctx);

			switch (Parameters.Type) {
			case SignatureInstrumentType.ClientProvidesSomeUnsupportedSignatureAlgorithms:
			case SignatureInstrumentType.ClientProvidesNoSupportedSignatureAlgorithms:
			case SignatureInstrumentType.ServerUsesUnsupportedSignatureAlgorithm2:
				// Instrumentation override.
				break;

			default:
				VerifySignatureParameters (ctx, parameters);
				break;
			}

			return parameters;
		}

		public override SignatureParameters GetServerSignatureParameters (ITlsContext ctx)
		{
			if (Parameters.ServerSignatureParameters != null)
				return Parameters.ServerSignatureParameters;
			else
				return base.GetServerSignatureParameters (ctx);
		}

		public override ClientCertificateParameters GetServerCertificateParameters (ITlsContext ctx)
		{
			if (Parameters.ServerCertificateParameters != null)
				return Parameters.ServerCertificateParameters;
			else
				return base.GetServerCertificateParameters (ctx);
		}

		public override SignatureAndHashAlgorithm SelectClientSignatureAlgorithm (ITlsContext ctx)
		{
			if (Parameters.ClientSignatureAlgorithm != null)
				return Parameters.ClientSignatureAlgorithm.Value;
			else if (Parameters.ClientSignatureParameters != null)
				return SelectSignatureAlgorithm (ctx, Parameters.ClientSignatureParameters);
			else
				return base.SelectClientSignatureAlgorithm (ctx);
		}

		public override SignatureAndHashAlgorithm SelectServerSignatureAlgorithm (ITlsContext ctx)
		{
			if (Parameters.ServerSignatureAlgorithm != null)
				return Parameters.ServerSignatureAlgorithm.Value;
			else if (Parameters.ServerSignatureParameters != null)
				return SelectSignatureAlgorithm (ctx, Parameters.ServerSignatureParameters);
			else
				return base.SelectServerSignatureAlgorithm (ctx);
		}

		public override void AssertTls12 (ITlsContext ctx)
		{
			Context.Assert (ctx.HasNegotiatedProtocol, "Has negotiated protocol");
			Context.Assert (ctx.NegotiatedProtocol, Is.EqualTo (TlsProtocolCode.Tls12), "Is TLS 1.2");
		}

		public override void AssertClientSignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			AssertTls12 (ctx);

			VerifySignatureAlgorithm (ctx, algorithm);

			if (Parameters.ExpectClientSignatureAlgorithm != null)
				Context.Expect (algorithm, Is.EqualTo (Parameters.ExpectClientSignatureAlgorithm.Value), "client signature algorithm");
		}

		public override void AssertServerSignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			Context.Assert (ctx.IsServer, Is.False, "is client");

			AssertTls12 (ctx);

			VerifySignatureAlgorithm (ctx, algorithm);

			if (Parameters.ExpectServerSignatureAlgorithm != null)
				Context.Expect (algorithm, Is.EqualTo (Parameters.ExpectServerSignatureAlgorithm.Value), "server signature algorithm");
			else if (ctx.HasCurrentSignatureParameters && ctx.CurrentSignatureParameters != null) {
				if (!ctx.CurrentSignatureParameters.SignatureAndHashAlgorithms.Contains (algorithm))
					throw new TlsException (AlertDescription.IlegalParameter);
			} else if (!algorithm.Equals (SignatureParameters.DefaultAlgorithm)) {
				throw new TlsException (AlertDescription.IlegalParameter);
			}
		}

		public override void AssertCertificateVerifySignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			Context.Assert (ctx.IsServer, Is.True, "is server");

			AssertTls12 (ctx);

			VerifySignatureAlgorithm (ctx, algorithm);

			if (Parameters.ExpectCertificateVerifySignatureAlgorithm != null) {
				Context.Expect (algorithm, Is.EqualTo (Parameters.ExpectCertificateVerifySignatureAlgorithm.Value), "certificate validate signature algorithm");
				return;
			}

			ClientCertificateParameters parameters;
			if (ctx.HasClientCertificateParameters && ctx.ClientCertificateParameters != null)
				parameters = ctx.ClientCertificateParameters;
			else
				parameters = null;

			if (parameters != null && parameters.HasSignatureParameters && parameters.SignatureParameters != null) {
				if (!parameters.SignatureParameters.SignatureAndHashAlgorithms.Contains (algorithm))
					throw new TlsException (AlertDescription.IlegalParameter);
			} else if (!algorithm.Equals (SignatureParameters.DefaultAlgorithm)) {
				throw new TlsException (AlertDescription.IlegalParameter);
			}
		}
	}
}

