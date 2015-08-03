//
// ConnectionInstrumentConnectionHandler.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.HttpFramework;

namespace Mono.Security.NewTls.TestFramework
{
	public class ConnectionInstrumentConnectionHandler : InstrumentationConnectionHandler
	{
		new public ConnectionInstrumentTestRunner Runner {
			get { return (ConnectionInstrumentTestRunner)base.Runner; }
		}

		public ConnectionInstrumentConnectionHandler (ConnectionInstrumentTestRunner runner)
			: base (runner)
		{
		}

		protected override async Task HandleClientRead (TestContext ctx, CancellationToken cancellationToken)
		{
			await ExpectBlob (ctx, Client, HandshakeInstrumentType.TestCompleted, cancellationToken);

			StartClientWrite ();
		}

		protected override async Task HandleClientWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			await WriteBlob (ctx, Client, HandshakeInstrumentType.TestCompleted, cancellationToken);
		}

		protected override async Task HandleServerRead (TestContext ctx, CancellationToken cancellationToken)
		{
			if (Runner.HasInstrument (HandshakeInstrumentType.SendBlobAfterReceivingFinish))
				await ExpectBlob (ctx, Server, HandshakeInstrumentType.SendBlobAfterReceivingFinish, cancellationToken);

			await ExpectBlob (ctx, Server, HandshakeInstrumentType.TestCompleted, cancellationToken);
		}

		protected override async Task HandleServerWrite (TestContext ctx, CancellationToken cancellationToken)
		{
			await WriteBlob (ctx, Server, HandshakeInstrumentType.TestCompleted, cancellationToken);
		}

		protected override Task HandleMainLoop (TestContext ctx, CancellationToken cancellationToken)
		{
			return FinishedTask;
		}

		protected override Task HandleClient (TestContext ctx, CancellationToken cancellationToken)
		{
			StartClientRead ();
			return FinishedTask;
		}

		protected override Task HandleServer (TestContext ctx, CancellationToken cancellationToken)
		{
			StartServerWrite ();
			StartServerRead ();
			return FinishedTask;
		}
	}
}

