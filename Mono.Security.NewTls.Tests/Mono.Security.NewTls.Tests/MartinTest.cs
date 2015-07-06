//
// MartinTest.cs
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
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Features;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;
	using TestFeatures;

	[Martin]
	[AsyncTestFixture]
	public class MartinTest
	{
		// [AsyncTest]
		public async Task TestClient (TestContext ctx, CancellationToken cancellationToken,
			[ConnectionProvider ("MonoWithNewTLS", Identifier = "ClientType")] ConnectionProviderType clientType,
			[ConnectionProvider ("MonoWithNewTLS", Identifier = "ServerType")] ConnectionProviderType serverType,
			[ConnectionInstrumentParameters (InstrumentationCategory.MartinTest)] ConnectionInstrumentParameters parameters,
			[ConnectionInstrumentTestRunner] ConnectionInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		// [AsyncTest]
		public async Task TestClientPuppy (TestContext ctx, CancellationToken cancellationToken,
			[ConnectionProvider ("Manual", Identifier = "ClientType")] ConnectionProviderType clientType,
			[ConnectionProvider ("MonoWithNewTLS", Identifier = "ServerType")] ConnectionProviderType serverType,
			[ConnectionInstrumentParameters (InstrumentationCategory.MartinTest)] ConnectionInstrumentParameters parameters,
			[ConnectionInstrumentTestRunner (MonoConnectionFlags.ServerInstrumentation)] ConnectionInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}

		[AsyncTest]
		public async Task TestServerPuppy (TestContext ctx, CancellationToken cancellationToken,
			[ConnectionProvider ("MonoWithNewTLS", Identifier = "ClientType")] ConnectionProviderType clientType,
			[ConnectionProvider ("Manual", Identifier = "ServerType")] ConnectionProviderType serverType,
			[ConnectionInstrumentParameters (InstrumentationCategory.MartinTest)] ConnectionInstrumentParameters parameters,
			[ConnectionInstrumentTestRunner (MonoConnectionFlags.ClientInstrumentation)] ConnectionInstrumentTestRunner runner)
		{
			await runner.Run (ctx, cancellationToken);
		}
	}
}

