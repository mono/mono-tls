//
// HashAlgorithmWrapper.cs
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
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.DotNetConsole
{
	public class HashAlgorithmWrapper : DisposeContext, IHashAlgorithm
	{
		MemoryStream content;

		public HashAlgorithmWrapper (HashAlgorithmType algorithm)
		{
			Algorithm = algorithm;
			HashSize = CreateAlgorithm ().HashSize;
			content = new MemoryStream ();
		}

		internal static bool IsAlgorithmSupported (HashAlgorithmType algorithm)
		{
			switch (algorithm) {
			case HashAlgorithmType.Md5:
			case HashAlgorithmType.Sha1:
			case HashAlgorithmType.Sha256:
			case HashAlgorithmType.Sha384:
			case HashAlgorithmType.Sha512:
				return true;
			default:
				return false;
			}
		}

		HashAlgorithm CreateAlgorithm ()
		{
			switch (Algorithm) {
			case HashAlgorithmType.Md5:
				return MD5.Create ();
			case HashAlgorithmType.Sha1:
				return SHA1.Create ();
			case HashAlgorithmType.Sha256:
				return SHA256.Create ();
			case HashAlgorithmType.Sha384:
				return SHA384.Create ();
			case HashAlgorithmType.Sha512:
				return SHA512.Create ();
			default:
				throw new NotSupportedException ();
			}
		}

		#region IHashAlgorithm implementation

		public void TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount)
		{
			content.Write (inputBuffer, inputOffset, inputCount);
		}

		public byte[] GetRunningHash ()
		{
			var algorithm = CreateAlgorithm ();
			algorithm.TransformFinalBlock (content.GetBuffer (), 0, (int)content.Length);
			return algorithm.Hash;
		}

		protected override void Clear ()
		{
			content = new MemoryStream ();
		}

		void IHashAlgorithm.Reset ()
		{
			Clear ();
		}

		public int HashSize {
			get;
			private set;
		}

		public HashAlgorithmType Algorithm {
			get;
			private set;
		}

		#endregion
	}
}

