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
	public class SignatureParameters
	{
		List<SignatureAndHashAlgorithm> signatureTypes;

		public IList<SignatureAndHashAlgorithm> SignatureAndHashAlgorithms {
			get {
				if (signatureTypes == null)
					signatureTypes = new List<SignatureAndHashAlgorithm> ();
				return signatureTypes;
			}
		}

		public void Add (SignatureAndHashAlgorithm algorithm)
		{
			SignatureAndHashAlgorithms.Add (algorithm);
		}

		public void Add (HashAlgorithmType hash)
		{
			SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (hash));
		}

		public void Add (HashAlgorithmType hash, SignatureAlgorithmType signature)
		{
			SignatureAndHashAlgorithms.Add (new SignatureAndHashAlgorithm (hash, signature));
		}

		public static SignatureParameters Create (params HashAlgorithmType[] hashTypes)
		{
			var parameters = new SignatureParameters ();
			foreach (var hash in hashTypes)
				parameters.Add (hash);
			return parameters;
		}

		public static SignatureParameters GetDefaultParameters ()
		{
			var parameters = new SignatureParameters ();
			parameters.EnsureDefaultValues ();
			return parameters;
		}

		internal void EnsureDefaultValues ()
		{
			if (SignatureAndHashAlgorithms.Count == 0) {
				Add (HashAlgorithmType.Sha512, SignatureAlgorithmType.Rsa);
				Add (HashAlgorithmType.Sha384, SignatureAlgorithmType.Rsa);
				Add (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa);
				Add (HashAlgorithmType.Sha1, SignatureAlgorithmType.Rsa);
			}
		}
	}
}

