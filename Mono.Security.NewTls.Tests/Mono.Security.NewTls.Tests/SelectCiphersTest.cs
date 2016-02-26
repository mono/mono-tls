//
// SelectCiphersTests.cs
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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.Interface;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.TestFramework;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.MonoTestFeatures;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;
	using TestFeatures;

	[AsyncTestFixture]
	public class SelectCiphersTests
	{
		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls10)]
		[InstrumentationCategory (InstrumentationCategory.SelectClientCipher)]
		public async Task TestClientTls10 (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			[CipherSuite] CipherSuiteCode cipher,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls11)]
		[InstrumentationCategory (InstrumentationCategory.SelectClientCipher)]
		public async Task TestClientTls11 (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			[CipherSuite] CipherSuiteCode cipher,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls12)]
		[InstrumentationCategory (InstrumentationCategory.SelectClientCipher)]
		public async Task TestClientTls12 (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			[CipherSuite] CipherSuiteCode cipher,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls10)]
		[InstrumentationCategory (InstrumentationCategory.SelectServerCipher)]
		public async Task TestServerTls10 (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			[CipherSuite] CipherSuiteCode cipher,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls11)]
		[InstrumentationCategory (InstrumentationCategory.SelectServerCipher)]
		public async Task TestServerTls11 (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			[CipherSuite] CipherSuiteCode cipher,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls12)]
		[InstrumentationCategory (InstrumentationCategory.SelectServerCipher)]
		public async Task TestServerTls12 (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			[CipherSuite] CipherSuiteCode cipher,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[InstrumentationCategory (InstrumentationCategory.SelectCipher)]
		public async Task TestConnection (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			CipherInstrumentParameters parameters,
			CipherInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}
	}
}

