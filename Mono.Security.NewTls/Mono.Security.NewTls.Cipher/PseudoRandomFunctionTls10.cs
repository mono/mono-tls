//
// Tls10PRF.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2014 Xamarin Inc. (http://www.xamarin.com)
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
using System.Text;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class PseudoRandomFunctionTls10 : PseudoRandomFunction
	{
		protected override SecureBuffer PRF (DisposeContext d, SecureBuffer secret, string label, SecureBuffer data, int length)
		{
			/* Secret Length calc exmplain from the RFC2246. Section 5
			 * 
			 * S1 and S2 are the two halves of the secret and each is the same
			 * length. S1 is taken from the first half of the secret, S2 from the
			 * second half. Their length is created by rounding up the length of the
			 * overall secret divided by two; thus, if the original secret is an odd
			 * number of bytes long, the last byte of S1 will be the same as the
			 * first byte of S2.
			 */

			// split secret in 2
			int secretLen = secret.Size >> 1;
			// rounding up
			if ((secret.Size & 0x1) == 0x1)
				secretLen++;

			// Secret 1
			var secret1 = d.CreateBuffer (secretLen);
			Buffer.BlockCopy (secret.Buffer, 0, secret1.Buffer, 0, secretLen);

			// Secret2
			var secret2 = d.CreateBuffer (secretLen);
			Buffer.BlockCopy (secret.Buffer, (secret.Size - secretLen), secret2.Buffer, 0, secretLen);

			// Secret 1 processing
			var p_md5 = d.Add (Expand (d, HMac.Create (HashAlgorithmType.Md5, secret1), label, data, length));

			// Secret 2 processing
			var p_sha = d.Add (Expand (d, HMac.Create (HashAlgorithmType.Sha1, secret2), label, data, length));

			// Perfor XOR of both results
			var masterSecret = new SecureBuffer (length);
			for (int i = 0; i < length; i++)
				masterSecret.Buffer[i] = (byte)(p_md5.Buffer[i] ^ p_sha.Buffer[i]);

			return masterSecret;
		}
	}
}

