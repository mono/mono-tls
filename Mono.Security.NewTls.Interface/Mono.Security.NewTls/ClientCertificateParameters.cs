//
// SignatureParameters.cs
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

namespace Mono.Security.NewTls
{
	public class ClientCertificateParameters
	{
		List<ClientCertificateType> certificateTypes;
		List<string> certificateAuthorities;
		SignatureParameters signatureParameters;

		public IList<ClientCertificateType> CertificateTypes {
			get {
				if (certificateTypes == null)
					certificateTypes = new List<ClientCertificateType> ();
				return certificateTypes;
			}
		}

		public IList<string> CertificateAuthorities {
			get {
				if (certificateAuthorities == null)
					certificateAuthorities = new List<string> ();
				return certificateAuthorities;
			}
		}

		public bool HasSignatureParameters {
			get { return signatureParameters != null && !signatureParameters.IsEmpty; }
		}

		public SignatureParameters SignatureParameters {
			get {
				if (signatureParameters == null)
					signatureParameters = new SignatureParameters ();
				return signatureParameters;
			}
		}

		internal void EnsureDefaultValues ()
		{
			// FIXME: Provide better default values
			if (CertificateTypes.Count == 0)
				CertificateTypes.Add (ClientCertificateType.RsaSign);
			SignatureParameters.EnsureDefaultValues ();
		}

		public static ClientCertificateParameters GetDefaultParameters ()
		{
			var defaultParameters = new ClientCertificateParameters ();
			defaultParameters.EnsureDefaultValues ();
			return defaultParameters;
		}
	}
}

