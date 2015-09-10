//
// MobileDependencyProvider.cs
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
using Mono.Security.NewTls.TestProvider;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.Tests;

[assembly: AsyncTestSuite (typeof (Mono.Security.NewTls.Tests.NewTlsTestFeatures), true)]
[assembly: DependencyProvider (typeof (Mono.Security.NewTls.iOS.MobileDependencyProvider))]

namespace Mono.Security.NewTls.iOS
{
	using Xamarin.AsyncTests;
	using Xamarin.AsyncTests.Framework;

	public class MobileDependencyProvider : NewTlsDependencyProvider
	{
		public static TestFramework GetFramework ()
		{
			DependencyInjector.RegisterAssembly (typeof(MobileDependencyProvider).Assembly);

			return TestFramework.GetLocalFramework (typeof(NewTlsTestFeatures).Assembly);
		}
	}
}
