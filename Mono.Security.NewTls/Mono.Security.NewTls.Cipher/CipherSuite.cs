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
using System.Text;
using System.Security.Cryptography;

using Mono.Security;
using Mono.Security.Cryptography;
using M = Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	internal abstract class CipherSuite
	{
		#region Static Fields

		public static byte[] EmptyArray = new byte[0];

		#endregion

		#region Properties

		public CipherAlgorithmType CipherAlgorithmType {
			get;
			private set;
		}

		public HashAlgorithmType HashAlgorithmType {
			get;
			private set;
		}

		public abstract int HashSize {
			get;
		}
		
		public ExchangeAlgorithmType ExchangeAlgorithmType {
			get;
			private set;
		}

		public CipherSuiteCode Code {
			get;
			private set;
		}

		public string Name {
			get;
			private set;
		}

		public abstract byte KeyMaterialSize {
			get;
		}

		public abstract byte ExpandedKeyMaterialSize {
			get;
		}

		public abstract short EffectiveKeyBits {
			get;
		}

		public abstract bool HasHMac {
			get;
		}

		public bool HasFixedIV {
			get { return FixedIvSize > 0; }
		}

		public abstract byte FixedIvSize {
			get;
		}
		
		public abstract byte BlockSize {
			get;
		}

		public virtual int KeyBlockSize {
			get { return (KeyMaterialSize + HashSize + FixedIvSize) << 1; }
		}

		public abstract HandshakeHashType HandshakeHashType {
			get;
		}

		#if DEBUG_FULL
		internal bool EnableDebugging {
			get; set;
		}
		#endif

		#endregion

		#region Constructors
		
		public CipherSuite (
			CipherSuiteCode code, CipherAlgorithmType cipherAlgorithmType, 
			HashAlgorithmType hashAlgorithmType, ExchangeAlgorithmType exchangeAlgorithmType)
		{
			Code = code;
			Name = code.ToString ();
			CipherAlgorithmType = cipherAlgorithmType;
			HashAlgorithmType = hashAlgorithmType;
			ExchangeAlgorithmType = exchangeAlgorithmType;
		}

		#endregion

		#region New APIs

		PseudoRandomFunction prf;

		public abstract CryptoParameters Initialize (bool isServer, TlsProtocolCode protocol);

		public PseudoRandomFunction PRF {
			get {
				if (prf == null)
					prf = CreatePseudoRandomFunction ();
				return prf;
			}
		}

		protected abstract PseudoRandomFunction CreatePseudoRandomFunction ();

		#endregion
	}
}
