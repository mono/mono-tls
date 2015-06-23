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

namespace Mono.Security.NewTls.Instrumentation
{
	public class SignatureInstrument : ISignatureProvider
	{
		public SignatureParameters ClientSignatureParameters {
			get; set;
		}

		public SignatureParameters ServerSignatureParameters {
			get; set;
		}

		public SignatureAndHashAlgorithm? ClientSignatureAlgorithm {
			get; set;
		}

		public SignatureAndHashAlgorithm? ServerSignatureAlgorithm {
			get; set;
		}

		public virtual SignatureParameters GetClientSignatureParameters (InstrumentationContext ctx)
		{
			if (ClientSignatureParameters != null)
				return ClientSignatureParameters;
			else
				return ctx.DefaultSignatureProvider.GetClientSignatureParameters (ctx);
		}

		public virtual SignatureParameters GetServerSignatureParameters (InstrumentationContext ctx)
		{
			if (ServerSignatureParameters != null)
				return ServerSignatureParameters;
			else
				return ctx.DefaultSignatureProvider.GetServerSignatureParameters (ctx);
		}

		public virtual void VerifySignatureAlgorithm (InstrumentationContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			ctx.DefaultSignatureProvider.VerifySignatureAlgorithm (ctx, algorithm);
		}

		public virtual void VerifySignatureParameters (InstrumentationContext ctx, SignatureParameters parameters)
		{
			ctx.DefaultSignatureProvider.VerifySignatureParameters (ctx, parameters);
		}

		public virtual SignatureAndHashAlgorithm SelectSignatureAlgorithm (InstrumentationContext ctx, SignatureParameters parameters)
		{
			return ctx.DefaultSignatureProvider.SelectSignatureAlgorithm (ctx, parameters);
		}

		public virtual SignatureAndHashAlgorithm SelectClientSignatureAlgorithm (InstrumentationContext ctx)
		{
			if (ClientSignatureAlgorithm != null)
				return ClientSignatureAlgorithm.Value;
			else if (ClientSignatureParameters != null)
				return ctx.DefaultSignatureProvider.SelectSignatureAlgorithm (ctx, ClientSignatureParameters);
			else
				return ctx.DefaultSignatureProvider.SelectClientSignatureAlgorithm (ctx);
		}

		public virtual SignatureAndHashAlgorithm SelectServerSignatureAlgorithm (InstrumentationContext ctx)
		{
			if (ServerSignatureAlgorithm != null)
				return ServerSignatureAlgorithm.Value;
			else if (ServerSignatureParameters != null)
				return ctx.DefaultSignatureProvider.SelectSignatureAlgorithm (ctx, ServerSignatureParameters);
			else
				return ctx.DefaultSignatureProvider.SelectServerSignatureAlgorithm (ctx);
		}

		public virtual void AssertProtocol (InstrumentationContext ctx, TlsProtocolCode protocol)
		{
			if (ctx.Protocol != protocol)
				throw new InstrumentException ("Expected TLS Protocol '{0}', got '{1}'.", ctx.Protocol, protocol);
		}

		public virtual void AssertSignatureAlgorithm (InstrumentationContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			if (ctx.Protocol != TlsProtocolCode.Tls12)
				throw new InstrumentException ("Expected TLS 1.2.");

			ctx.DefaultSignatureProvider.VerifySignatureAlgorithm (ctx, algorithm);

			if (ServerSignatureAlgorithm != null && !ServerSignatureAlgorithm.Value.Equals (algorithm))
				throw new InstrumentException ("Expected SignatureAlgoritum '{0}', got '{1}'.", ServerSignatureAlgorithm.Value, algorithm);
		}
	}
}

