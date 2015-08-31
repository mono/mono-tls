//
// InstrumentationConnectionTypeAttribute.cs
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
using Xamarin.AsyncTests.Framework;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFeatures
{
	using TestFramework;

	[AttributeUsage (AttributeTargets.Class, AllowMultiple = false)]
	public class InstrumentationConnectionProviderAttribute : TestParameterAttribute, ITestParameterSource<InstrumentationConnectionProvider>
	{
		public InstrumentationConnectionProviderAttribute (string filter = null, TestFlags flags = TestFlags.Browsable)
			: base (filter, flags)
		{
		}

		public IEnumerable<InstrumentationConnectionProvider> GetParameters (TestContext ctx, string argument)
		{
			var category = ctx.GetParameter<InstrumentationCategory> ();

			InstrumentationConnectionFilter filter;
			if (!ctx.TryGetParameter<InstrumentationConnectionFilter> (out filter)) {
				var flags = InstrumentationTestRunner.GetConnectionFlags (ctx, category);

				InstrumentationConnectionFlags explicitFlags;
				if (ctx.TryGetParameter<InstrumentationConnectionFlags> (out explicitFlags))
					flags |= explicitFlags;

				filter = new InstrumentationConnectionFilter (category, flags);
			}

			return filter.GetSupportedProviders (ctx, argument).Cast<InstrumentationConnectionProvider> ();
		}
	}
}
