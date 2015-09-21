//
// CipherSuiteAttribute.cs
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
using System.Linq;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFeatures
{
	using TestFramework;

	[AttributeUsage (AttributeTargets.Parameter, AllowMultiple = false)]
	public class CipherSuiteAttribute : TestParameterAttribute, ITestParameterSource<CipherSuiteCode>
	{
		public CipherSuiteCode Cipher {
			get; set;
		}

		public CipherSuiteAttribute (string filter = null)
			: base (filter, TestFlags.Browsable | TestFlags.ContinueOnError)
		{
		}

		public CipherSuiteAttribute (CipherSuiteCode cipher)
			: base (null, TestFlags.Browsable | TestFlags.ContinueOnError)
		{
			Cipher = cipher;
		}

		[Flags]
		enum FilterFlags {
			None		= 0,
			RSA		= 1,
			DHE		= 2,
			AEAD		= 4,
			CBC		= 8,
			ALL		= 16
		}

		static bool CipherMatchesFilterFlags (CipherSuiteCode code, FilterFlags flags)
		{
			if ((flags & FilterFlags.ALL) != 0)
				return true;

			bool rsa = (flags & FilterFlags.RSA) != 0;
			bool dhe = (flags & FilterFlags.DHE) != 0;
			bool aead = (flags & FilterFlags.AEAD) != 0;
			bool cbc = (flags & FilterFlags.CBC) != 0;

			switch (code) {
			// Galois-Counter Cipher Suites.
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
				return dhe | aead;

			// Galois-Counter with Legacy RSA Key Exchange.
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384:
				return rsa | aead;

			// Diffie-Hellman Cipher Suites
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
				return dhe | cbc;

			// Legacy AES Cipher Suites
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA:
				return rsa | cbc;

			default:
				return false;
			}
		}

		static bool FilterCipher (CipherSuiteCode cipher, string filter)
		{
			if (string.IsNullOrEmpty (filter))
				return true;

			FilterFlags? includeFlags = null;
			FilterFlags excludeFlags = FilterFlags.None;

			var parts = filter.Split (':');
			foreach (var part in parts) {
				var name = part;
				if (part [0] == '+' || part [0] == '-')
					name = name.Substring (1);

				var flag = (FilterFlags)Enum.Parse (typeof(FilterFlags), name, true);
				if (part [0] == '-') {
					excludeFlags |= flag;
				} else {
					if (includeFlags == null)
						includeFlags = FilterFlags.None;
					includeFlags |= flag;
				}
			}

			if (CipherMatchesFilterFlags (cipher, excludeFlags))
				return false;
			if (includeFlags != null && !CipherMatchesFilterFlags (cipher, includeFlags.Value))
				return false;

			return true;
		}

		public IEnumerable<CipherSuiteCode> GetParameters (TestContext ctx, string filter)
		{
			ProtocolVersions version;
			if (!ctx.TryGetParameter<ProtocolVersions> (out version))
				version = ProtocolVersions.Tls12;

			var protocol = MonoConnectionHelper.GetProtocolCode (version);

			CipherSuiteCode[] ciphers;
			switch (protocol) {
			case TlsProtocolCode.Tls12:
				ciphers = CipherInstrumentTestRunner.CiphersTls12;
				break;
			case TlsProtocolCode.Tls11:
			case TlsProtocolCode.Tls10:
				ciphers = CipherInstrumentTestRunner.CiphersTls10;
				break;
			default:
				ctx.AssertFail ("Invalid protocol version `{0}'.", version);
				return null;
			}

			return ciphers.Where (c => FilterCipher (c, filter));
		}
	}
}

