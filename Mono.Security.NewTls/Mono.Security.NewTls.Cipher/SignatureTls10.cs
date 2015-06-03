//
// SignatureTls10.cs
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
using System.Security.Cryptography;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class SignatureTls10 : Signature
	{
		public SecureBuffer Signature {
			get;
			private set;
		}

		public SignatureTls10 (TlsBuffer incoming)
		{
			Signature = Add (incoming.ReadSecureBuffer (incoming.ReadInt16 ()));
		}

		public SignatureTls10 ()
		{
		}

		public override void Write (TlsStream stream)
		{
			stream.Write ((short)Signature.Size);
			stream.Write (Signature.Buffer);
		}

		public override void Create (SecureBuffer data, AsymmetricAlgorithm key)
		{
			using (var d = new DisposeContext ()) {
				var alg = d.Add (new MD5SHA1 ());
				alg.TransformFinalBlock (data.Buffer, 0, data.Size);
				Signature = new SecureBuffer (PKCS1.Sign_v15 ((RSA)key, alg, alg.Hash));
			}
		}

		public override bool Verify (SecureBuffer data, AsymmetricAlgorithm key)
		{
			using (var d = new DisposeContext ()) {
				var alg = d.Add (new MD5SHA1 ());
				alg.TransformFinalBlock (data.Buffer, 0, data.Size);
				return PKCS1.Verify_v15 ((RSA)key, alg, alg.Hash, Signature.Buffer);
			}
		}
	}
}

