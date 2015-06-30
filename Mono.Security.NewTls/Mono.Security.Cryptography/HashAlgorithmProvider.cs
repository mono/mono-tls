//
// HashAlgorithmProvider.cs
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
using Mono.Security.NewTls;

namespace Mono.Security.Cryptography
{
	public static class HashAlgorithmProvider
	{
		public static IHashAlgorithm CreateAlgorithm (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5Sha1:
				return new MD5SHA1 ();
			case HashAlgorithmType.Md5:
				return new MD5CryptoServiceProvider ();
			case HashAlgorithmType.Sha1:
				return new SHA1CryptoServiceProvider ();
			case HashAlgorithmType.Sha224:
				return new SHA224Managed ();
			case HashAlgorithmType.Sha256:
				return new SHA256Managed ();
			case HashAlgorithmType.Sha384:
				return new SHA384Managed ();
			case HashAlgorithmType.Sha512:
				return new SHA512Managed ();
			default:
				throw new NotSupportedException ();
			}
		}

		public static bool IsAlgorithmSupported (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5Sha1:
			case HashAlgorithmType.Md5:
			case HashAlgorithmType.Sha1:
			case HashAlgorithmType.Sha224:
			case HashAlgorithmType.Sha256:
			case HashAlgorithmType.Sha384:
			case HashAlgorithmType.Sha512:
				return true;
			default:
				return false;
			}
		}

		public static IHashAlgorithm CreateAlgorithmFromName (string name)
		{
			switch (name.ToUpperInvariant ()) {
			case "MD5SHA1":
				return CreateAlgorithm (HashAlgorithmType.Md5Sha1);
			case "MD5":
				return CreateAlgorithm (HashAlgorithmType.Md5);
			case "SHA1":
				return CreateAlgorithm (HashAlgorithmType.Sha1);
			case "SHA224":
				return CreateAlgorithm (HashAlgorithmType.Sha224);
			case "SHA256":
				return CreateAlgorithm (HashAlgorithmType.Sha256);
			case "SHA384":
				return CreateAlgorithm (HashAlgorithmType.Sha384);
			case "SHA512":
				return CreateAlgorithm (HashAlgorithmType.Sha384);
			default:
				throw new NotSupportedException ();
			}
		}

		public static string GetAlgorithmName (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5Sha1:
				return "MD5SHA1";
			case HashAlgorithmType.Md5:
				return "MD5";
			case HashAlgorithmType.Sha1:
				return "SHA1";
			case HashAlgorithmType.Sha224:
				return "SHA224";
			case HashAlgorithmType.Sha256:
				return "SHA256";
			case HashAlgorithmType.Sha384:
				return "SHA384";
			case HashAlgorithmType.Sha512:
				return "SHA512";
			default:
				throw new NotSupportedException ();
			}
		}

		public static string GetOID (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5Sha1:
				return null;
			case HashAlgorithmType.Md5:
				return "1.2.840.113549.2.5";
			case HashAlgorithmType.Sha1:
				return "1.3.14.3.2.26";
			case HashAlgorithmType.Sha224:
				return "2.16.840.1.101.3.4.2.4";
			case HashAlgorithmType.Sha256:
				return "2.16.840.1.101.3.4.2.1";
			case HashAlgorithmType.Sha384:
				return "2.16.840.1.101.3.4.2.2";
			case HashAlgorithmType.Sha512:
				return "2.16.840.1.101.3.4.2.3";
			default:
				throw new NotSupportedException ();
			}
		}

		public static int GetHashSize (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5Sha1:
				return 288;
			case HashAlgorithmType.Md5:
				return 128;
			case HashAlgorithmType.Sha1:
				return 160;
			case HashAlgorithmType.Sha224:
				return 224;
			case HashAlgorithmType.Sha256:
				return 256;
			case HashAlgorithmType.Sha384:
				return 384;
			case HashAlgorithmType.Sha512:
				return 512;
			default:
				throw new NotSupportedException ();
			}
		}
	}
}

