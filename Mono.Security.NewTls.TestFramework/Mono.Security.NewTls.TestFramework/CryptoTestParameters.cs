//
// CryptoTestParameters.cs
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

namespace Mono.Security.NewTls.TestFramework
{
	public class CryptoTestParameters
	{
		public TlsProtocolCode Protocol {
			get;
			private set;
		}

		public CipherSuiteCode Code {
			get;
			private set;
		}

		public bool IsServer {
			get { return true; }
		}

		public byte[] Key {
			get;
			private set;
		}

		public byte[] ImplicitNonce {
			get;
			private set;
		}

		public byte[] ExplicitNonce {
			get;
			private set;
		}

		public byte[] MAC {
			get;
			private set;
		}

		public byte[] IV {
			get;
			private set;
		}

		public bool IsGCM {
			get;
			private set;
		}
		
		public bool EnableDebugging {
			get; set;
		}

		public byte ExtraPaddingBlocks {
			get; set;
		}

		public static CryptoTestParameters CreateCBC (TlsProtocolCode protocol, CipherSuiteCode code, byte[] key, byte[] mac, byte[] iv)
		{
			return new CryptoTestParameters {
				Protocol = protocol, Code = code, Key = key, MAC = mac, IV = iv
			};
		}

		public static CryptoTestParameters CreateGCM (TlsProtocolCode protocol, CipherSuiteCode code, byte[] key, byte[] implNonce, byte[] explNonce)
		{
			return new CryptoTestParameters {
				Protocol = protocol, Code = code, Key = key, ImplicitNonce = implNonce, ExplicitNonce = explNonce, IsGCM = true
			};
		}
	}
}

