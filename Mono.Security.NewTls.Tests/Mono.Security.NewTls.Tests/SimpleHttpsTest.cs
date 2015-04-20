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
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Resources;
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

	[Work]
	[AsyncTestFixture (Timeout = 5000)]
	public class SimpleHttpsTest
	{
		[NewTlsTestFeatures.SelectHttpsProvider]
		public HttpProviderType HttpsProvider {
			get;
			private set;
		}

		[NewTlsTestFeatures.SelectHttpTestMode]
		public HttpTestMode TestMode {
			get;
			private set;
		}

		[NewTlsTestFeatures.SelectServerCertificate]
		public ServerCertificateType ServerCertificateType {
			get;
			private set;
		}

		public static IEnumerable<Handler> GetParameters (TestContext ctx, string filter)
		{
			yield return new HelloWorldHandler ("Hello World");
		}

		[Work]
		[AsyncTest]
		public Task Run (TestContext ctx, CancellationToken cancellationToken, [HttpsTestHost] HttpServer server, [SimpleHttpsHandler] Handler handler)
		{
			return HttpsTestRunner.Run (ctx, cancellationToken, server, handler);
		}
	}
}

