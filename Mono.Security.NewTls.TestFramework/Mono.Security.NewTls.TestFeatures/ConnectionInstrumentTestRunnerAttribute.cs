//
// ConnectionInstrumentTestRunnerAttribute.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.TestRunners;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFeatures
{
	using TestFramework;

	public class ConnectionInstrumentTestRunnerAttribute : TestHostAttribute, ITestHost<ConnectionInstrumentTestRunner>
	{
		public ConnectionInstrumentTestRunnerAttribute ()
			: base (typeof (ConnectionInstrumentTestRunnerAttribute), TestFlags.Hidden | TestFlags.PathHidden)
		{
		}

		public ConnectionInstrumentTestRunnerAttribute (MonoConnectionFlags flags)
			: base (typeof (ConnectionInstrumentTestRunnerAttribute), TestFlags.Hidden | TestFlags.PathHidden)
		{
			ConnectionFlags = flags;
		}

		public MonoConnectionFlags? ConnectionFlags {
			get;
			private set;
		}

		public ConnectionInstrumentTestRunner CreateInstance (TestContext ctx)
		{
			return MonoTestFeatures.CreateTestRunner<ConnectionInstrumentParameters,ConnectionInstrumentTestRunner> (
				ctx, (s, c, p, f) => new ConnectionInstrumentTestRunner (s, c, p, f), ConnectionFlags);
		}
	}
}

