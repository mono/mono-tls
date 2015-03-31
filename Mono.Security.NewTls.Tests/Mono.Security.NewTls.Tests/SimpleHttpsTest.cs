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
using Xamarin.WebTests.Portable;
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

	class HttpsTestRunner : TestRunner
	{
		public HttpsProviderType ProviderType {
			get;
			private set;
		}

		public HttpsTestRunner (HttpsProviderType type)
		{
			ProviderType = type;
		}

		protected override Request CreateRequest (TestContext ctx, HttpServer server, Handler handler, Uri uri)
		{
			ctx.LogMessage ("CREATE REQUEST: {0} {1}", ProviderType, uri);
			var provider = DependencyInjector.Get<IHttpsProvider> ();
			var request = provider.CreateRequest (ProviderType, uri);
			return new TraditionalRequest (request);
		}

		protected override Task<Response> RunInner (TestContext ctx, CancellationToken cancellationToken, HttpServer server, Handler handler, Request request)
		{
			var traditionalRequest = (TraditionalRequest)request;
			return traditionalRequest.SendAsync (ctx, cancellationToken);
		}
	}

	[Work]
	[AsyncTestFixture (Timeout = 5000)]
	public class SimpleHttpsTest : ITestHost<HttpServer>
	{
		[NewTlsTestFeatures.SelectHttpsProvider]
		public HttpsProviderType HttpsProvider {
			get;
			private set;
		}

		public HttpServer CreateInstance (TestContext ctx)
		{
			var endpointSupport = DependencyInjector.Get<IPortableEndPointSupport> ();
			var endpoint = endpointSupport.GetLoopbackEndpoint (9999);

			var provider = DependencyInjector.Get<IHttpsProvider> ();
			return provider.CreateServer (endpoint, ResourceManager.DefaultServerCertificate);
		}

		public static IEnumerable<Handler> GetParameters (TestContext ctx, string filter)
		{
			yield return new HelloWorldHandler ("Hello World");
		}

		[AsyncTest]
		public Task Run (TestContext ctx, CancellationToken cancellationToken, [TestHost] HttpServer server, [SimpleHttpsHandler] Handler handler)
		{
			var runner = new HttpsTestRunner (HttpsProvider);
			return runner.Run (ctx, cancellationToken, server, handler, null);
		}

	}
}

