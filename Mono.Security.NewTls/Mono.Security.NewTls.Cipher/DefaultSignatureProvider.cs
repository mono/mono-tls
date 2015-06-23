//
// DefaultSignatureProvider.cs
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

namespace Mono.Security.NewTls.Cipher
{
	using Instrumentation;

	class DefaultSignatureProvider : ISignatureProvider
	{
		static ISignatureProvider defaultSignatureProvider;

		public static ISignatureProvider Instance {
			get {
				if (defaultSignatureProvider == null)
					Interlocked.CompareExchange<ISignatureProvider> (ref defaultSignatureProvider, new DefaultSignatureProvider (), null);
				return defaultSignatureProvider;
			}
		}

		DefaultSignatureProvider ()
		{
		}

		public SignatureParameters GetClientSignatureParameters (TlsContext ctx)
		{
			if (ctx.Configuration.UserSettings == null || !ctx.Configuration.UserSettings.HasSignatureParameters)
				return null;

			return ctx.Configuration.UserSettings.SignatureParameters;
		}

		SignatureParameters ISignatureProvider.GetClientSignatureParameters (InstrumentationContext ctx)
		{
			return GetClientSignatureParameters ((TlsContext)ctx);
		}

		public SignatureParameters GetServerSignatureParameters (TlsContext ctx)
		{
			if (ctx.Session.SignatureParameters != null)
				return ctx.Session.SignatureParameters;

			if (ctx.Configuration.UserSettings != null && ctx.Configuration.UserSettings.HasSignatureParameters)
				return ctx.Configuration.UserSettings.SignatureParameters;

			return SignatureParameters.GetDefaultParameters ();
		}

		SignatureParameters ISignatureProvider.GetServerSignatureParameters (InstrumentationContext ctx)
		{
			return GetServerSignatureParameters ((TlsContext)ctx);
		}

		public SignatureAndHashAlgorithm SelectSignatureAlgorithm (InstrumentationContext ctx, SignatureParameters parameters)
		{
			foreach (var algorithm in parameters.SignatureAndHashAlgorithms) {
				if (SignatureHelper.IsAlgorithmSupported (algorithm))
					return algorithm;
			}

			throw new TlsException (AlertDescription.HandshakeFailure, "No supported signature type available.");
		}

		SignatureAndHashAlgorithm ISignatureProvider.SelectSignatureAlgorithm (InstrumentationContext ctx, SignatureParameters parameters)
		{
			return SelectSignatureAlgorithm ((TlsContext)ctx, parameters);
		}

		public SignatureAndHashAlgorithm SelectClientSignatureAlgorithm (TlsContext ctx)
		{
			SignatureParameters parameters;
			if (ctx.HandshakeParameters.ClientCertificateParameters != null && ctx.HandshakeParameters.ClientCertificateParameters.HasSignatureParameters)
				parameters = ctx.HandshakeParameters.ClientCertificateParameters.SignatureParameters;
			else if (ctx.Session.SignatureParameters != null)
				parameters = ctx.Session.SignatureParameters;
			else
				parameters = SignatureParameters.GetDefaultParameters ();

			return SelectSignatureAlgorithm (ctx, parameters);
		}

		SignatureAndHashAlgorithm ISignatureProvider.SelectClientSignatureAlgorithm (InstrumentationContext ctx)
		{
			return SelectClientSignatureAlgorithm ((TlsContext)ctx);
		}

		public SignatureAndHashAlgorithm SelectServerSignatureAlgorithm (TlsContext ctx)
		{
			var parameters = GetServerSignatureParameters (ctx);
			return SelectSignatureAlgorithm (ctx, parameters);
		}

		SignatureAndHashAlgorithm ISignatureProvider.SelectServerSignatureAlgorithm (InstrumentationContext ctx)
		{
			return SelectServerSignatureAlgorithm ((TlsContext)ctx);
		}

		public void VerifySignatureAlgorithm (InstrumentationContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			SignatureHelper.VerifySignatureAlgorithm (algorithm);
		}

		public void VerifySignatureParameters (InstrumentationContext ctx, SignatureParameters parameters)
		{
			SignatureHelper.VerifySignatureParameters (parameters);
		}

		public void AssertProtocol (TlsContext ctx, TlsProtocolCode protocol)
		{
			if (!ctx.HasNegotiatedProtocol || ctx.NegotiatedProtocol != protocol)
				throw new TlsException (AlertDescription.ProtocolVersion);
		}

		void ISignatureProvider.AssertProtocol (InstrumentationContext ctx, TlsProtocolCode protocol)
		{
			AssertProtocol ((TlsContext)ctx, protocol);
		}

		public void AssertSignatureAlgorithm (TlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			if (!SignatureHelper.IsAlgorithmSupported (algorithm))
				throw new TlsException (AlertDescription.IlegalParameter);
		}

		void ISignatureProvider.AssertSignatureAlgorithm (InstrumentationContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			AssertSignatureAlgorithm ((TlsContext)ctx, algorithm);
		}
	}
}

