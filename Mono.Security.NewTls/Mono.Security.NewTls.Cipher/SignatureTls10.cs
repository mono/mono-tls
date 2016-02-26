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
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Cipher
{
	class SignatureTls10 : Signature
	{
		public override TlsProtocolCode Protocol {
			get { return TlsProtocolCode.Tls10; }
		}

		public override HashAlgorithmType HashAlgorithm {
			get { return HashAlgorithmType.Md5Sha1; }
		}

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

		public override void Create (byte[] hash, AsymmetricAlgorithm key)
		{
			Signature = SignatureHelper.CreateSignature (HashAlgorithmType.Md5Sha1, hash, key);
		}

		public override bool Verify (byte[] hash, AsymmetricAlgorithm key)
		{
			return SignatureHelper.VerifySignature (HashAlgorithmType.Md5Sha1, hash, key, Signature);
		}
	}
}

