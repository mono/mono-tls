// Transport Security Layer (TLS)
// Copyright (c) 2003-2004 Carlos Guzman Alvarez
// Copyright (C) 2006 Novell, Inc (http://www.novell.com)
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
using System.IO;
using System.Security.Cryptography;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	internal sealed class TlsCipherSuite10 : CipherSuite
	{
		public TlsCipherSuite10 (
			CipherSuiteCode code, CipherAlgorithmType cipherAlgorithmType, 
			HashAlgorithmType hashAlgorithmType, ExchangeAlgorithmType exchangeAlgorithmType)
			:base (code, cipherAlgorithmType, hashAlgorithmType, exchangeAlgorithmType)
		{
		}

		public override HandshakeHashType HandshakeHashType {
			get { return HandshakeHashType.MD5SHA1; }
		}

		public override short EffectiveKeyBits {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
					return 128;
				case CipherAlgorithmType.Aes256:
					return 256;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override int HashSize {
			get {
				switch (HashAlgorithmType) {
				case HashAlgorithmType.Md5:
					return 16;
				case HashAlgorithmType.Sha1:
					return 20;
				case HashAlgorithmType.Sha256:
					return 32;
				case HashAlgorithmType.None:
					return 0;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override byte KeyMaterialSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
					return 16;
				case CipherAlgorithmType.Aes256:
					return 32;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override byte ExpandedKeyMaterialSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
					return 16;
				case CipherAlgorithmType.Aes256:
					return 32;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override bool HasHMac {
			get { return true; }
		}

		public override byte FixedIvSize {
			get { return BlockSize; }
		}

		public override byte BlockSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
				case CipherAlgorithmType.Aes256:
					return 16;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override CryptoParameters Initialize (bool isServer, TlsProtocolCode protocol)
		{
			return new CbcBlockCipher (isServer, protocol, this);
		}

		protected override PseudoRandomFunction CreatePseudoRandomFunction ()
		{
			return new PseudoRandomFunctionTls10 ();
		}
	}
}
