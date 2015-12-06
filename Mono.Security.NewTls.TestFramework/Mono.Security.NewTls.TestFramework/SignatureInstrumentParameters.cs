//
// SignatureInstrumentParameters.cs
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
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFramework
{
	using TestFeatures;

	[SignatureInstrumentParameters]
	public class SignatureInstrumentParameters : InstrumentationParameters
	{
		public SignatureInstrumentType Type {
			get;
			private set;
		}

		public SignatureInstrumentParameters (InstrumentationCategory category, SignatureInstrumentType type, string identifier, ICertificate certificate)
			: base (category, identifier, certificate)
		{
			Type = type;
		}

		protected SignatureInstrumentParameters (SignatureInstrumentParameters other)
			: base (other)
		{
			Type = other.Type;
			ClientSignatureParameters = other.ClientSignatureParameters;
			ServerSignatureParameters = other.ServerSignatureParameters;
			ClientSignatureAlgorithm = other.ClientSignatureAlgorithm;
			ServerSignatureAlgorithm = other.ServerSignatureAlgorithm;
			ExpectClientSignatureAlgorithm = other.ExpectClientSignatureAlgorithm;
			ExpectServerSignatureAlgorithm = other.ExpectServerSignatureAlgorithm;
			ServerCertificateParameters = other.ServerCertificateParameters;
			CertificateVerifySignatureAlgorithm = other.CertificateVerifySignatureAlgorithm;
			ExpectCertificateVerifySignatureAlgorithm = other.ExpectCertificateVerifySignatureAlgorithm;
		}

		public override ConnectionParameters DeepClone ()
		{
			return new SignatureInstrumentParameters (this);
		}

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

		public SignatureAndHashAlgorithm? ExpectClientSignatureAlgorithm {
			get; set;
		}

		public SignatureAndHashAlgorithm? ExpectServerSignatureAlgorithm {
			get; set;
		}

		public ClientCertificateParameters ServerCertificateParameters {
			get; set;
		}

		public SignatureAndHashAlgorithm? CertificateVerifySignatureAlgorithm {
			get; set;
		}

		public SignatureAndHashAlgorithm? ExpectCertificateVerifySignatureAlgorithm {
			get; set;
		}
	}
}

