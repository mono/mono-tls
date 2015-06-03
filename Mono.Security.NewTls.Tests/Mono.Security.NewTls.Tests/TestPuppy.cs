//
// TestPuppy.cs
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
using Xamarin.WebTests.HttpHandlers;
using Xamarin.WebTests.TestRunners;
using Xamarin.WebTests.Features;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.Tests
{
	[Puppy]
	[AsyncTestFixture (Timeout = 5000)]
	public class TestPuppy
	{
		[AsyncTest]
		public Task Run (TestContext ctx, CancellationToken cancellationToken)
		{
			var factory = DependencyInjector.Get<ConnectionProviderFactory> ();
			var provider = factory.GetProvider (ConnectionProviderType.MonoWithNewTLS);

			var runner = new MyPuppyTestRunner (provider);
			return runner.Run (ctx, cancellationToken);
		}

		class MyPuppyTestRunner : PuppyTestRunner
		{
			public ConnectionProvider Provider {
				get;
				private set;
			}

			public MyPuppyTestRunner (ConnectionProvider provider)
			{
				Provider = provider;
			}

			public override Request CreateRequest (TestContext ctx)
			{
				var uri = new Uri (GetPuppyURL (ctx));
				var request = Provider.HttpProvider.CreateWebRequest (uri);
				return new TraditionalRequest (request);
			}
		}
	}
}

