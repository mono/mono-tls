//
// SimpleConnectionTest.cs
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

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	public class ServerTestHostAttribute : TestHostAttribute, ITestHost<IServer>
	{
		public ServerTestHostAttribute ()
			: base (typeof (ServerTestHostAttribute))
		{
		}

		public IServer CreateInstance (TestContext ctx)
		{
			var providerType = ctx.GetParameter<ConnectionProviderType> ("ServerType");
			var parameters = ctx.GetParameter<ClientAndServerParameters> ();
			var provider = DependencyInjector.Get<IConnectionProvider> ();
			return provider.CreateServer (providerType, parameters);
		}
	}

	public class ClientTestHostAttribute : TestHostAttribute, ITestHost<IClient>
	{
		public ClientTestHostAttribute ()
			: base (typeof (ClientTestHostAttribute))
		{
		}

		public IClient CreateInstance (TestContext ctx)
		{
			var providerType = ctx.GetParameter<ConnectionProviderType> ("ClientType");
			var parameters = ctx.GetParameter<ClientAndServerParameters> ();
			var provider = DependencyInjector.Get<IConnectionProvider> ();
			return provider.CreateClient (providerType, parameters);
		}
	}

	class ConnectionParameterAttribute : TestParameterAttribute, ITestParameterSource<ClientAndServerParameters>
	{
		public ConnectionParameterAttribute ()
			: base (null, TestFlags.Browsable)
		{
		}

		public IEnumerable<ClientAndServerParameters> GetParameters (TestContext ctx, string filter)
		{
			return SimpleConnectionTest.GetConnectionParameters (ctx, filter);
		}
	}

	[AsyncTestFixture]
	public class SimpleConnectionTest
	{
		[NewTlsTestFeatures.SelectConnectionProvider]
		public ConnectionProviderType ServerType {
			get;
			private set;
		}

		[NewTlsTestFeatures.SelectConnectionProvider]
		public ConnectionProviderType ClientType {
			get;
			private set;
		}

		public static IEnumerable<ClientAndServerParameters> GetConnectionParameters (TestContext ctx, string filter)
		{
			yield return new ClientAndServerParameters ("simple", ResourceManager.SelfSignedServerCertificate) {
				VerifyPeerCertificate = false
			};
		}

		[AsyncTest]
		public async Task TestConnection (TestContext ctx,
			[ConnectionParameter] ClientAndServerParameters parameters,
			[ServerTestHost] IServer server, [ClientTestHost] IClient client)
		{
			ctx.LogMessage ("TEST CONNECTION: {0} {1} {2}", parameters, server, client);

			var handler = ClientAndServerHandlerFactory.HandshakeAndDone.Create (server, client);
			await handler.WaitForConnection ();
			ctx.LogMessage ("TEST CONNECTION #1");
			await handler.Run ();

			ctx.LogMessage ("TEST CONNECTION DONE");
		}

	}
}

