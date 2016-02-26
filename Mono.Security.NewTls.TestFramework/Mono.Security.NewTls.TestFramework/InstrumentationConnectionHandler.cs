//
// InstrumentationConnectionHandler.cs
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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.MonoTestFramework;
using Xamarin.WebTests.HttpFramework;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class InstrumentationConnectionHandler : MonoConnectionHandler
	{
		new public InstrumentationTestRunner Runner {
			get { return (InstrumentationTestRunner)base.Runner; }
		}

		new protected InstrumentationParameters Parameters {
			get { return Runner.Parameters; }
		}

		public InstrumentationConnectionHandler (InstrumentationTestRunner runner)
			: base (runner)
		{
		}

		protected Task ExpectBlob (TestContext ctx, ICommonConnection connection, HandshakeInstrumentType type, CancellationToken cancellationToken)
		{
			return ExpectBlob (ctx, connection, type.ToString (), Instrumentation.GetTextBuffer (type), cancellationToken);
		}

		protected Task WriteBlob (TestContext ctx, ICommonConnection connection, HandshakeInstrumentType type, CancellationToken cancellationToken)
		{
			return WriteBlob (ctx, connection, type.ToString (), Instrumentation.GetTextBuffer (type), cancellationToken);
		}
	}
}

