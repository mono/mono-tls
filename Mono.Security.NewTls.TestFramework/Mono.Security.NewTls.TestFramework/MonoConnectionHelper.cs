//
// MonoConnectionHelper.cs
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
using System.Threading;
using System.Threading.Tasks;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;

namespace Mono.Security.NewTls.TestFramework
{
	public static class MonoConnectionHelper
	{
		public static void ExpectAlert (TestContext ctx, Task t, AlertDescription expectedAlert, string message)
		{
			ctx.Assert (t.IsFaulted, Is.True, "#1:" + message);
			var baseException = t.Exception.GetBaseException ();
			if (baseException is AggregateException) {
				var aggregate = baseException as AggregateException;
				ctx.Assert (aggregate.InnerExceptions.Count, Is.EqualTo (2), "#2a:" + message);
				var authExcType = aggregate.InnerExceptions [0].GetType ();
				ctx.Assert (authExcType.FullName, Is.EqualTo ("System.Security.Authentication.AuthenticationException"), "#2b:" + message);
				baseException = aggregate.InnerExceptions [1];
			}
			ctx.Assert (baseException, Is.InstanceOf<TlsException> (), "#2:" + message);
			var alert = ((TlsException)baseException).Alert;
			ctx.Assert (alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3:" + message);
			ctx.Assert (alert.Description, Is.EqualTo (expectedAlert), "#4:" + message);
		}
	}
}

