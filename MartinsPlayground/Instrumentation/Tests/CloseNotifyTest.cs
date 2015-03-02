//
// CloseNotifyTest.cs
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
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;
using Mono.Security.NewTls.Negotiation;
using Mono.Security.NewTls.Handshake;
using NUnit.Framework;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;
	using Resources;

	[Explicit]
	[Category ("Martin")]
	class CloseNotifyTest : ConnectionTest
	{
		public CloseNotifyTest (TestConfiguration config, ClientAndServerFactory factory)
			: base (config, factory)
		{
		}

		ClientAndServerParameters GetDefaultParameters ()
		{
			return new ClientAndServerParameters {
				VerifyPeerCertificate = false
			};
		}

		[Test]
		public async void Simple ()
		{
			await Run (MyFlags.None);
		}

		[Test]
		public async void ServerSendsExtra ()
		{
			await Run (MyFlags.ServerSendsExtra, typeof (IOException));
		}

		[Test]
		public async void ClientSendsExtra ()
		{
			await Run (MyFlags.ClientSendsExtra, typeof (IOException));
		}

		[Test]
		public async void ServerClosesFirst ()
		{
			await Run (MyFlags.ServerClosesFirst);
		}

		[Test]
		public async void ClientClosesFirst ()
		{
			await Run (MyFlags.ClientClosesFirst);
		}

		[Test]
		public async void DuplicateClose ()
		{
			await Run (MyFlags.DuplicateClose);
		}

		async Task Run (MyFlags flags, Type expectedException = null, ClientAndServerParameters parameters = null, Action<ClientAndServer> action = null)
		{
			if (parameters == null)
				parameters = GetDefaultParameters ();

			try {
				if (Configuration.EnableDebugging)
					parameters.EnableDebugging = true;
				using (var connection = (ClientAndServer)await Factory.Start (parameters)) {
					if (action != null)
						action (connection);
					var handler = new MyConnectionHandler (connection, flags);
					await handler.Run ();
				}
				if (expectedException != null)
					Assert.Fail ("Expected an exception of type {0}", expectedException);
			} catch (Exception ex) {
				if (expectedException != null) {
					Assert.That (ex, Is.InstanceOf (expectedException));
				} else {
					DebugHelper.WriteLine ("ERROR: {0} {1}", ex.GetType (), ex);
					throw;
				}
			}
		}

		[Flags]
		enum MyFlags {
			None = 0,
			ServerSendsExtra = 1,
			ClientSendsExtra = 2,
			ServerClosesFirst = 4,
			ClientClosesFirst = 8,
			DuplicateClose = 16
		}

		class MyConnectionHandler : ClientAndServerHandler
		{
			public readonly MyFlags Flags;

			public MyConnectionHandler (IConnection connection, MyFlags flags)
				: base ((ClientAndServer)connection)
			{
				Flags = flags;
			}

			protected override async Task MainLoop (ILineBasedStream serverStream, ILineBasedStream clientStream)
			{
				await serverStream.WriteLineAsync ("SERVER OK");
				var line = await clientStream.ReadLineAsync ();
				if (!line.Equals ("SERVER OK"))
					throw new ConnectionException ("Got unexpected output from server: '{0}'", line);
				await clientStream.WriteLineAsync ("CLIENT OK");
				line = await serverStream.ReadLineAsync ();
				if (!line.Equals ("CLIENT OK"))
					throw new ConnectionException ("Got unexpected output from client: '{0}'", line);
				if ((Flags & MyFlags.ServerSendsExtra) != 0)
					await serverStream.WriteLineAsync ("EXTRA LINE FROM SERVER!");
				if ((Flags & MyFlags.ClientSendsExtra) != 0)
					await clientStream.WriteLineAsync ("EXTRA LINE FROM CLIENT!");
				if ((Flags & MyFlags.ServerClosesFirst) != 0) {
					await Connection.Server.Shutdown (true, false);
					line = await clientStream.ReadLineAsync ();
					if (line != null)
						throw new ConnectionException ("Got unexpected line after server sent close");
				}
				if ((Flags & MyFlags.ClientClosesFirst) != 0) {
					await Connection.Client.Shutdown (true, false);
					line = await serverStream.ReadLineAsync ();
					if (line != null)
						throw new ConnectionException ("Got unexpected line after client sent close");
				}
				if ((Flags & MyFlags.DuplicateClose) != 0)
					await Connection.Shutdown (true, true);
				await Connection.Shutdown (true, true);
				Connection.Dispose ();
			}
		}

	}
}

