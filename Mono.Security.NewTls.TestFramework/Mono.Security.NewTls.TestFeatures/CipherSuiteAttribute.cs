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
using Xamarin.WebTests.Providers;
using Mono.Security.Interface;

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

		public IEnumerable<CipherSuiteCode> GetParameters (TestContext ctx, string filter)
		{
			ProtocolVersions version;
			if (!ctx.TryGetParameter<ProtocolVersions> (out version))
				version = ProtocolVersions.Tls12;

			var protocol = MonoConnectionHelper.GetProtocolCode (version);

			CipherSuiteCode[] ciphers;
			switch (protocol) {
			case TlsProtocolCode.Tls12:
				ciphers = CipherList.CiphersTls12;
				break;
			case TlsProtocolCode.Tls11:
			case TlsProtocolCode.Tls10:
				ciphers = CipherList.CiphersTls10;
				break;
			default:
				ctx.AssertFail ("Invalid protocol version `{0}'.", version);
				return null;
			}

			return ciphers.Where (c => CipherList.FilterCipher (c, filter));
		}
	}
}

