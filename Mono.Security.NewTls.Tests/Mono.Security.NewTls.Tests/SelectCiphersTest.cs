//
// SelectCiphersTest.cs
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
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Features;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;
	using TestFeatures;

	class SelectCipherSuiteAttribute : TestParameterAttribute, ITestParameterSource<CipherSuiteCode>
	{
		public SelectCipherSuiteAttribute (string name)
		{
			Identifier = name;
		}

		public SelectCipherSuiteAttribute (string name, CipherSuiteCode code)
			: base (code.ToString ())
		{
			Identifier = name;
		}

		public IEnumerable<CipherSuiteCode> GetParameters (TestContext ctx, string filter)
		{
			if (filter != null) {
				CipherSuiteCode code;
				if (!Enum.TryParse<CipherSuiteCode> (filter, out code))
					ctx.AssertFail ("Invalid cipher code '{0}'.", filter);

				yield return code;
				yield break;
			}

			// Galois-Counter Cipher Suites.
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;

			// Galois-Counter with Legacy RSA Key Exchange.
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384;

			// Diffie-Hellman Cipher Suites
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;

			// Legacy AES Cipher Suites
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
		}
	}

	[AsyncTestFixture]
	public class SelectCiphersTest
	{
		[ConnectionProvider (ProviderFlags = ConnectionProviderFlags.CanSelectCiphers)]
		public ConnectionProviderType ServerType {
			get;
			private set;
		}

		[ConnectionProvider (ProviderFlags = ConnectionProviderFlags.CanSelectCiphers)]
		public ConnectionProviderType ClientType {
			get;
			private set;
		}

		[AsyncTest]
		public async Task SelectClientCipher (TestContext ctx, CancellationToken cancellationToken,
			[MonoClientAndServerTestType (SelectCiphers = true)] MonoClientAndServerTestType type,
			[SelectCipherSuite ("ClientCipher")] CipherSuiteCode clientCipher,
			[MonoClientAndServerTestRunner] MonoClientAndServerTestRunner runner)
		{
			ctx.Assert (clientCipher, Is.EqualTo (runner.Parameters.ExpectedClientCipher.Value), "expected cipher");

			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		public async Task SelectServerCipher (TestContext ctx, CancellationToken cancellationToken,
			[MonoClientAndServerTestType (SelectCiphers = true)] MonoClientAndServerTestType type,
			[SelectCipherSuite ("ServerCipher")] CipherSuiteCode serverCipher,
			[MonoClientAndServerTestRunner] MonoClientAndServerTestRunner runner)
		{
			ctx.Assert (serverCipher, Is.EqualTo (runner.Parameters.ExpectedServerCipher.Value), "expected cipher");

			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		public async Task InvalidCipher (TestContext ctx, CancellationToken cancellationToken,
			[MonoClientAndServerTestType (SelectCiphers = true)] MonoClientAndServerTestType type,
			[SelectCipherSuite ("ServerCipher", CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)] CipherSuiteCode serverCipher,
			[SelectCipherSuite ("ClientCipher", CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)] CipherSuiteCode clientCipher,
			[MonoClientAndServerTestRunner] MonoClientAndServerTestRunner runner)
		{
			await runner.ExpectAlert (ctx, AlertDescription.HandshakeFailure, cancellationToken);
		}
	}
}

