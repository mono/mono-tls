//
// HttpsTest.cs
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
using Xamarin.WebTests.Framework;
using Xamarin.WebTests.Handlers;
using Xamarin.AsyncTests.Portable;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.NewTls.Tests
{
	[AttributeUsage (AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = false)]
	public class SimpleHttpsHandlerAttribute : TestParameterAttribute, ITestParameterSource<Handler>
	{
		public SimpleHttpsHandlerAttribute (string filter = null, TestFlags flags = TestFlags.Browsable)
			: base (filter, flags)
		{
		}

		public IEnumerable<Handler> GetParameters (TestContext ctx, string filter)
		{
			return SimpleHttpsTest.GetParameters (ctx, filter);
		}
	}

	class HttpsTestRunner : TraditionalTestRunner
	{
		protected override void ConfigureRequest (TestContext ctx, HttpServer server, Uri uri, Handler handler, Request request)
		{
			var provider = DependencyInjector.Get<IHttpsConnectionProvider> ();
			var traditionalRequest = (TraditionalRequest)request;
			provider.InitializeHttpRequest (traditionalRequest.Request);
			base.ConfigureRequest (ctx, server, uri, handler, request);
		}

		protected override async Task<Response> RunInner (TestContext ctx, CancellationToken cancellationToken, HttpServer server, Uri uri, Handler handler)
		{
			return await base.RunInner (ctx, cancellationToken, server, uri, handler);
		}
	}

	[Work]
	[AsyncTestFixture (Timeout = 5000)]
	public class SimpleHttpsTest : ITestHost<HttpServer>
	{
		public HttpServer CreateInstance (TestContext ctx)
		{
			var support = DependencyInjector.Get<IPortableEndPointSupport> ();
			return new HttpServer (support.GetLoopbackEndpoint (9999), false, true);
		}

		public static IEnumerable<Handler> GetParameters (TestContext ctx, string filter)
		{
			yield return new HelloWorldHandler ("Hello World");
		}

		[AsyncTest]
		public Task Run (TestContext ctx, CancellationToken cancellationToken, [TestHost] HttpServer server, [SimpleHttpsHandler] Handler handler)
		{
			var runner = new HttpsTestRunner ();
			return runner.Run (ctx, cancellationToken, server, handler, null);
		}

	}
}

