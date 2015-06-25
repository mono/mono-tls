//
// SignatureProvider.cs
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

namespace Mono.Security.NewTls
{
	using Instrumentation;

	public class SignatureProvider
	{
		public virtual SignatureParameters GetClientSignatureParameters (ITlsContext ctx)
		{
			if (ctx.IsServer)
				throw new InvalidOperationException ();

			var parameters = ctx.ConfigurationProvider.ClientSignatureParameters;
			if (parameters != null)
				VerifySignatureParameters (ctx, parameters);

			return parameters;
		}

		public virtual SignatureParameters GetServerSignatureParameters (ITlsContext ctx)
		{
			if (!ctx.IsServer)
				throw new InvalidOperationException ();

			if (ctx.HasCurrentSignatureParameters)
				return ctx.CurrentSignatureParameters;

			var parameters = ctx.ConfigurationProvider.ServerSignatureParameters;
			if (parameters != null)
				return parameters;

			return SignatureParameters.GetDefaultParameters ();
		}

		public void AssertProtocol (ITlsContext ctx, TlsProtocolCode protocol)
		{
			if (!ctx.HasNegotiatedProtocol || ctx.NegotiatedProtocol != protocol)
				throw new TlsException (AlertDescription.ProtocolVersion);
		}

		public void VerifySignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			if (!ctx.IsAlgorithmSupported (algorithm))
				throw new TlsException (AlertDescription.IlegalParameter);
		}

		public void VerifySignatureParameters (ITlsContext ctx, SignatureParameters parameters)
		{
			foreach (var algorithm in parameters.SignatureAndHashAlgorithms) {
				if (!ctx.IsAlgorithmSupported (algorithm))
					throw new TlsException (AlertDescription.IlegalParameter);
			}
		}

		public SignatureAndHashAlgorithm SelectSignatureAlgorithm (ITlsContext ctx, SignatureParameters parameters)
		{
			if (parameters == null)
				parameters = SignatureParameters.GetDefaultParameters ();

			foreach (var algorithm in parameters.SignatureAndHashAlgorithms) {
				if (ctx.IsAlgorithmSupported (algorithm))
					return algorithm;
			}

			throw new TlsException (AlertDescription.HandshakeFailure, "No supported signature type available.");
		}

		public virtual SignatureAndHashAlgorithm SelectClientSignatureAlgorithm (ITlsContext ctx)
		{
			if (ctx.IsServer)
				throw new InvalidOperationException ();

			SignatureParameters parameters;
			if (ctx.HasClientCertificateParameters && ctx.ClientCertificateParameters.HasSignatureParameters)
				parameters = ctx.ClientCertificateParameters.SignatureParameters;
			else if (ctx.HasCurrentSignatureParameters)
				parameters = ctx.CurrentSignatureParameters;
			else
				parameters = GetClientSignatureParameters (ctx);

			return SelectSignatureAlgorithm (ctx, parameters);
		}

		public virtual SignatureAndHashAlgorithm SelectServerSignatureAlgorithm (ITlsContext ctx)
		{
			if (!ctx.IsServer)
				throw new InvalidOperationException ();

			var parameters = GetServerSignatureParameters (ctx);
			return SelectSignatureAlgorithm (ctx, parameters);
		}

		public virtual void AssertClientSignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			if (!ctx.IsServer)
				throw new InvalidOperationException ();

			VerifySignatureAlgorithm (ctx, algorithm);
		}

		public virtual void AssertServerSignatureAlgorithm (ITlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			if (ctx.IsServer)
				throw new InvalidOperationException ();

			VerifySignatureAlgorithm (ctx, algorithm);
		}
	}
}

