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

			var parameters = Parameters.ClientSignatureParameters;
			if (parameters == null)
				return base.GetClientSignatureParameters (ctx);

			VerifySignatureParameters (ctx, parameters);
			return parameters;
		}

		public override SignatureParameters GetServerSignatureParameters (ITlsContext ctx)
		{
			if (Parameters.ServerSignatureParameters != null)
				return Parameters.ServerSignatureParameters;
			else
				return base.GetServerSignatureParameters (ctx);
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

		void AssertTls12 (ITlsContext ctx)
		{
			Context.Assert (ctx.HasNegotiatedProtocol, "Has negotiated protocol");
			Context.Assert (ctx.NegotiatedProtocol, Is.EqualTo (TlsProtocolCode.Tls12), "Is TLS 1.2");
		}

		public override void AssertClientSignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			AssertTls12 (ctx);

			base.AssertClientSignatureAlgorithm (ctx, algorithm);

			VerifySignatureAlgorithm (ctx, algorithm);

			if (Parameters.ExpectClientSignatureAlgorithm != null)
				Context.Expect (algorithm, Is.EqualTo (Parameters.ExpectClientSignatureAlgorithm.Value), "client signature algorithm");
		}

		public override void AssertServerSignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			AssertTls12 (ctx);

			base.AssertServerSignatureAlgorithm (ctx, algorithm);

			VerifySignatureAlgorithm (ctx, algorithm);

			if (Parameters.ExpectServerSignatureAlgorithm != null)
				Context.Expect (algorithm, Is.EqualTo (Parameters.ExpectServerSignatureAlgorithm.Value), "server signature algorithm");
		}
	}
}

