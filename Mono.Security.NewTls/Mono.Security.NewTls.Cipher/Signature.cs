//
// Signature.cs
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
	abstract class Signature : DisposeContext
	{
		public abstract TlsProtocolCode Protocol {
			get;
		}

		public abstract HashAlgorithmType HashAlgorithm {
			get;
		}

		public abstract void Write (TlsStream stream);

		public void Create (SecureBuffer data, AsymmetricAlgorithm key)
		{
			var hash = CreateHash (HashAlgorithm, data);
			Create (hash, key);
		}

		public bool Verify (SecureBuffer data, AsymmetricAlgorithm key)
		{
			var hash = CreateHash (HashAlgorithm, data);
			return Verify (hash, key);
		}

		public abstract void Create (byte[] hash, AsymmetricAlgorithm key);

		public abstract bool Verify (byte[] hash, AsymmetricAlgorithm key);

		static byte[] CreateHash (HashAlgorithmType type, SecureBuffer data)
		{
			if (!HashAlgorithmProvider.IsAlgorithmSupported (type))
				throw new TlsException (AlertDescription.IlegalParameter);
			using (var d = new DisposeContext ()) {
				var algorithm = d.Add (HashAlgorithmProvider.CreateAlgorithm (type));
				algorithm.TransformBlock (data.Buffer, 0, data.Size);
				return algorithm.GetRunningHash ();
			}
		}

		public static Signature Read (TlsProtocolCode protocol, TlsBuffer incoming)
		{
			switch (protocol) {
			case TlsProtocolCode.Tls10:
				return new SignatureTls10 (incoming);
			case TlsProtocolCode.Tls11:
				return new SignatureTls11 (incoming);
			case TlsProtocolCode.Tls12:
				return new SignatureTls12 (incoming);
			default:
				throw new NotSupportedException ();
			}
		}
	}
}

