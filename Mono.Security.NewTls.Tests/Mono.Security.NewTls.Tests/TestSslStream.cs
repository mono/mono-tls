//
// TestSslStream.cs
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
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;

using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.AsyncTests.Constraints;

using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestFramework;
using Xamarin.WebTests.TestRunners;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	[Work]
	[AsyncTestFixture (Timeout = 5000)]
	public class TestSslStream
	{
		[AsyncTest]
		[ConnectionTestCategory (ConnectionTestCategory.HttpsWithMono)]
		public async Task TestMonoConnection (TestContext ctx, CancellationToken cancellationToken,
			ConnectionTestProvider provider, SslStreamTestParameters parameters,
			SslStreamTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ConnectionTestCategory (ConnectionTestCategory.HttpsWithDotNet)]
		public async Task TestDotNetConnection (TestContext ctx, CancellationToken cancellationToken,
			ConnectionTestProvider provider, SslStreamTestParameters parameters,
			SslStreamTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ProtocolVersion (ProtocolVersions.Tls12)]
		[ConnectionTestCategory (ConnectionTestCategory.SslStreamWithTls12)]
		public async Task TestDotNetConnectionTls12 (TestContext ctx, CancellationToken cancellationToken,
			ConnectionTestProvider provider, SslStreamTestParameters parameters,
			SslStreamTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ManualClient]
		[ManualSslStream]
		[ConnectionTestFlags (ConnectionTestFlags.ManualClient)]
		[ConnectionTestCategory (ConnectionTestCategory.MartinTest)]
		public async Task TestManualClient (TestContext ctx, CancellationToken cancellationToken,
			ConnectionTestProvider provider, SslStreamTestParameters parameters,
			SslStreamTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ManualServer]
		[ManualSslStream]
		[ConnectionTestFlags (ConnectionTestFlags.ManualServer)]
		[ConnectionTestCategory (ConnectionTestCategory.MartinTest)]
		public async Task TestManualServer (TestContext ctx, CancellationToken cancellationToken,
			ConnectionTestProvider provider, SslStreamTestParameters parameters,
			SslStreamTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

	}
}

