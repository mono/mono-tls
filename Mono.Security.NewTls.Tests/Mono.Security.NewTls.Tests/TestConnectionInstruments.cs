//
// TestConnectionInstruments.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;
	using TestFeatures;

	[AsyncTestFixture]
	public class TestConnectionInstruments
	{
		[AsyncTest]
		[InstrumentationCategory (InstrumentationCategory.ClientConnection)]
		public async Task TestClient (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[InstrumentationCategory (InstrumentationCategory.ServerConnection)]
		public async Task TestServer (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[InstrumentationCategory (InstrumentationCategory.Connection)]
		public async Task TestConnection (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[InstrumentationCategory (InstrumentationCategory.CertificateChecks)]
		public Task TestInvalidCertificates (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			return runner.Run (ctx, cancellationToken);
		}

		[Martin]
		[AsyncTest]
		[InstrumentationCategory (InstrumentationCategory.MartinTest)]
		public Task MartinTest (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			return runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ManualClient]
		[InstrumentationCategory (InstrumentationCategory.MartinTest)]
		[InstrumentationConnectionFlags (InstrumentationConnectionFlags.ManualClient)]
		public Task ClientPuppy (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			return runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		[ManualServer]
		[InstrumentationCategory (InstrumentationCategory.MartinTest)]
		[InstrumentationConnectionFlags (InstrumentationConnectionFlags.ManualServer)]
		public Task ServerPuppy (TestContext ctx, CancellationToken cancellationToken,
			InstrumentationConnectionProvider provider,
			GenericConnectionInstrumentParameters parameters,
			GenericConnectionInstrumentTestRunner runner)
		{
			return runner.Run (ctx, cancellationToken);
		}
	}
}

