//
// CipherList.cs
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
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFramework
{
	public static class CipherList
	{
		public static readonly CipherSuiteCode[] CiphersTls10 = {
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
		};

		public static readonly CipherSuiteCode[] CiphersTls12 = {
			// ECDHE Galois-Counter Ciphers.
			CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// ECDHE AES Ciphers.
			CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
			CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

			// Galois-Counter Cipher Suites.
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,

			// Galois-Counter with Legacy RSA Key Exchange.
			CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384,

			// Diffie-Hellman Cipher Suites
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,

			// Legacy AES Cipher Suites
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256,
			CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA,
			CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA
		};

		[Flags]
		public enum FilterFlags
		{
			None		= 0,
			Rsa		= 1,
			Dhe		= 2,
			Aead		= 4,
			Cbc		= 8,
			EcDhe		= 16,
			All		= 32
		}

		public static bool CipherMatchesFilterFlags (CipherSuiteCode code, FilterFlags flags)
		{
			if ((flags & FilterFlags.All) != 0)
				return true;

			bool rsa = (flags & FilterFlags.Rsa) != 0;
			bool dhe = (flags & FilterFlags.Dhe) != 0;
			bool ecdhe = (flags & FilterFlags.EcDhe) != 0;
			bool aead = (flags & FilterFlags.Aead) != 0;
			bool cbc = (flags & FilterFlags.Cbc) != 0;

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

				// ECDHE Galois-Counter Ciphers.
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
				return ecdhe | aead;

				// ECDHE AES Ciphers.
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
				return ecdhe | cbc;

			default:
				return false;
			}
		}

		public static bool FilterCipher (CipherSuiteCode cipher, string filter)
		{
			if (filter == null)
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

		public static bool ProviderSupportsCipher (ClientAndServerProvider provider, CipherSuiteCode cipher)
		{
			return ProviderSupportsCipher (provider.Client, cipher) && ProviderSupportsCipher (provider.Server, cipher);
		}

		public static bool ProviderSupportsCipher (ConnectionProvider provider, CipherSuiteCode cipher)
		{
			bool aead = (provider.Flags & ConnectionProviderFlags.SupportsAeadCiphers) != 0;
			bool tls12 = (provider.Flags & ConnectionProviderFlags.SupportsTls12) != 0;
			bool ecdhe = (provider.Flags & ConnectionProviderFlags.SupportsEcDheCiphers) != 0;

			switch (cipher) {
			// Galois-Counter Cipher Suites.
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
				return aead;

				// Galois-Counter with Legacy RSA Key Exchange.
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384:
				return aead;

				// Diffie-Hellman Cipher Suites
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
				return tls12;

				// Legacy AES Cipher Suites
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA:
				return true;

				// ECDHE Galois-Counter Ciphers.
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
				return aead && ecdhe;

				// ECDHE AES Ciphers.
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuiteCode.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
				return ecdhe;

			default:
				return false;
			}
		}

		public static bool ValidateCipherList (ClientAndServerProvider provider, ICollection<CipherSuiteCode> ciphers)
		{
			return ciphers == null || ciphers.Any (cipher => ProviderSupportsCipher (provider, cipher));
		}
	}
}

