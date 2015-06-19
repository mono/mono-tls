//
// PKCS1.cs - Implements PKCS#1 primitives.
//
// Author:
//	Sebastien Pouliot  <sebastien@xamarin.com>
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004 Novell, Inc (http://www.novell.com)
// Copyright 2013 Xamarin Inc. (http://www.xamarin.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Security.Cryptography;
using Mono.Security.NewTls;

namespace Mono.Security.Cryptography { 

	// References:
	// a.	PKCS#1: RSA Cryptography Standard 
	//	http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/index.html
	
	internal sealed class PKCS1 {

		private PKCS1 () 
		{
		}

		private static bool Compare (byte[] array1, byte[] array2) 
		{
			bool result = (array1.Length == array2.Length);
			if (result) {
				for (int i=0; i < array1.Length; i++)
					if (array1[i] != array2[i])
						return false;
			}
			return result;
		}
	
		private static byte[] xor (byte[] array1, byte[] array2) 
		{
			byte[] result = new byte [array1.Length];
			for (int i=0; i < result.Length; i++)
				result[i] = (byte) (array1[i] ^ array2[i]);
			return result;
		}
	
		private static byte[] emptySHA1   = { 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09 };
		private static byte[] emptySHA256 = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
		private static byte[] emptySHA384 = { 0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b };
		private static byte[] emptySHA512 = { 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e };
	
		private static byte[] GetEmptyHash (HashAlgorithm hash) 
		{
			if (hash is SHA1)
				return emptySHA1;
			else if (hash is SHA256)
				return emptySHA256;
			else if (hash is SHA384)
				return emptySHA384;
			else if (hash is SHA512)
				return emptySHA512;
			else
				return hash.ComputeHash ((byte[])null);
		}

		public static byte[] I2OSP (byte[] x, int size) 
		{
			byte[] result = new byte [size];
			Buffer.BlockCopy (x, 0, result, (result.Length - x.Length), x.Length);
			return result;
		}
	
		// PKCS #1 v.2.1, Section 4.2
		// OS2IP converts an octet string to a nonnegative integer.
		public static byte[] OS2IP (byte[] x) 
		{
			int i = 0;
			while ((x [i++] == 0x00) && (i < x.Length)) {
				// confuse compiler into reporting a warning with {}
			}
			i--;
			if (i > 0) {
				byte[] result = new byte [x.Length - i];
				Buffer.BlockCopy (x, i, result, 0, result.Length);
				return result;
			}
			else
				return x;
		}
	
		// PKCS #1 v.2.1, Section 5.1.1
		public static byte[] RSAEP (RSA rsa, byte[] m) 
		{
			// c = m^e mod n
			return rsa.EncryptValue (m);
		}
	
		// PKCS #1 v.2.1, Section 5.1.2
		public static byte[] RSADP (RSA rsa, byte[] c) 
		{
			// m = c^d mod n
			// Decrypt value may apply CRT optimizations
			return rsa.DecryptValue (c);
		}
	
		// PKCS #1 v.2.1, Section 5.2.1
		public static byte[] RSASP1 (RSA rsa, byte[] m) 
		{
			// first form: s = m^d mod n
			// Decrypt value may apply CRT optimizations
			return rsa.DecryptValue (m);
		}
	
		// PKCS #1 v.2.1, Section 5.2.2
		public static byte[] RSAVP1 (RSA rsa, byte[] s) 
		{
			// m = s^e mod n
			return rsa.EncryptValue (s);
		}

		// PKCS #1 v.2.1, Section 8.2.1
		// RSASSA-PKCS1-V1_5-SIGN (K, M)
		public static byte[] Sign_v15 (RSA rsa, IHashAlgorithm hash, byte[] hashValue)
		{
			int size = (rsa.KeySize >> 3); // div 8
			byte[] EM = Encode_v15 (hash, hashValue, size);
			byte[] m = OS2IP (EM);
			byte[] s = RSASP1 (rsa, m);
			byte[] S = I2OSP (s, size);
			return S;
		}

		// PKCS #1 v.2.1, Section 8.2.2
		// RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)
		public static bool Verify_v15 (RSA rsa, IHashAlgorithm hash, byte[] hashValue, byte[] signature)
		{
			return Verify_v15 (rsa, hash, hashValue, signature, false);
		}

		// DO NOT USE WITHOUT A VERY GOOD REASON
		public static bool Verify_v15 (RSA rsa, IHashAlgorithm hash, byte[] hashValue, byte[] signature, bool tryNonStandardEncoding)
		{
			int size = (rsa.KeySize >> 3); // div 8
			byte[] s = OS2IP (signature);
			byte[] m = RSAVP1 (rsa, s);
			byte[] EM2 = I2OSP (m, size);
			byte[] EM = Encode_v15 (hash, hashValue, size);
			bool result = Compare (EM, EM2);
			if (result || !tryNonStandardEncoding)
				return result;

			// NOTE: some signatures don't include the hash OID (pretty lame but real)
			// and compatible with MS implementation. E.g. Verisign Authenticode Timestamps

			// we're making this "as safe as possible"
			if ((EM2 [0] != 0x00) || (EM2 [1] != 0x01))
				return false;
			int i;
			for (i = 2; i < EM2.Length - hashValue.Length - 1; i++) {
				if (EM2 [i] != 0xFF)
					return false;
			}
			if (EM2 [i++] != 0x00)
				return false;

			byte [] decryptedHash = new byte [hashValue.Length];
			Buffer.BlockCopy (EM2, i, decryptedHash, 0, decryptedHash.Length);
			return Compare (decryptedHash, hashValue);
		}

		// PKCS #1 v.2.1, Section 9.2
		// EMSA-PKCS1-v1_5-Encode
		public static byte[] Encode_v15 (IHashAlgorithm hash, byte[] hashValue, int emLength)
		{
			if (hashValue.Length != (hash.HashSize >> 3))
				throw new CryptographicException ("bad hash length for " + hash.ToString ());

			// DigestInfo ::= SEQUENCE {
			//	digestAlgorithm AlgorithmIdentifier,
			//	digest OCTET STRING
			// }

			byte[] t = null;

			string hashName = HashAlgorithmProvider.GetAlgorithmName (hash.Algorithm);
			string oid = CryptoConfig.MapNameToOID (hashName);
			if (oid != null)
			{
				ASN1 digestAlgorithm = new ASN1 (0x30);
				digestAlgorithm.Add (new ASN1 (CryptoConfig.EncodeOID (oid)));
				digestAlgorithm.Add (new ASN1 (0x05));		// NULL
				ASN1 digest = new ASN1 (0x04, hashValue);
				ASN1 digestInfo = new ASN1 (0x30);
				digestInfo.Add (digestAlgorithm);
				digestInfo.Add (digest);

				t = digestInfo.GetBytes ();
			}
			else
			{
				// There are no valid OID, in this case t = hashValue
				// This is the case of the MD5SHA hash algorithm
				t = hashValue;
			}

			Buffer.BlockCopy (hashValue, 0, t, t.Length - hashValue.Length, hashValue.Length);

			int PSLength = System.Math.Max (8, emLength - t.Length - 3);
			// PS = PSLength of 0xff

			// EM = 0x00 | 0x01 | PS | 0x00 | T
			byte[] EM = new byte [PSLength + t.Length + 3];
			EM [1] = 0x01;
			for (int i=2; i < PSLength + 2; i++)
				EM[i] = 0xff;
			Buffer.BlockCopy (t, 0, EM, PSLength + 3, t.Length);

			return EM;
		}

		static internal string HashNameFromOid (string oid, bool throwOnError = true)
		{
			switch (oid) {
			case "1.2.840.113549.1.1.2":	// MD2 with RSA encryption 
				return "MD2";
			case "1.2.840.113549.1.1.3":	// MD4 with RSA encryption 
				return "MD4";
			case "1.2.840.113549.1.1.4":	// MD5 with RSA encryption 
				return "MD5";
			case "1.2.840.113549.1.1.5":	// SHA-1 with RSA Encryption 
			case "1.3.14.3.2.29":		// SHA1 with RSA signature 
			case "1.2.840.10040.4.3":	// SHA1-1 with DSA
				return "SHA1";
			case "1.2.840.113549.1.1.11":	// SHA-256 with RSA Encryption
				return "SHA256";
			case "1.2.840.113549.1.1.12":	// SHA-384 with RSA Encryption
				return "SHA384";
			case "1.2.840.113549.1.1.13":	// SHA-512 with RSA Encryption
				return "SHA512";
			case "1.3.36.3.3.1.2":
				return "RIPEMD160";
			default:
				if (throwOnError)
					throw new CryptographicException ("Unsupported hash algorithm: " + oid);
				return null;
			}
		}
	}
}
