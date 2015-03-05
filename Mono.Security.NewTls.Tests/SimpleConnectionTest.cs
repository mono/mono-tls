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

	public class ServerTestHostAttribute : TestHostAttribute, ITestHost<IServerTestHost>
	{
		public ServerTestHostAttribute ()
			: base (typeof (ServerTestHostAttribute))
		{
		}

		public IServerTestHost CreateInstance (TestContext ctx)
		{
			var providerType = ctx.GetParameter<ConnectionProviderType> ("ServerType");
			var serverParameters = ctx.GetParameter<ServerParameters> ();
			var provider = DependencyInjector.Get<IConnectionProvider> ();
			return provider.CreateServer (providerType, serverParameters);
		}
	}

	public class ClientTestHostAttribute : TestHostAttribute, ITestHost<IClientTestHost>
	{
		public ClientTestHostAttribute ()
			: base (typeof (ClientTestHostAttribute))
		{
		}

		public IClientTestHost CreateInstance (TestContext ctx)
		{
			var providerType = ctx.GetParameter<ConnectionProviderType> ("ClientType");
			var clientParameters = ctx.GetParameter<ClientParameters> ();
			var provider = DependencyInjector.Get<IConnectionProvider> ();
			return provider.CreateClient (providerType, clientParameters);
		}
	}

	class ServerParameterAttribute : TestParameterAttribute, ITestParameterSource<ServerParameters>
	{
		public ServerParameterAttribute ()
			: base (null, TestFlags.Browsable)
		{
		}

		public IEnumerable<ServerParameters> GetParameters (TestContext ctx, string filter)
		{
			return SimpleConnectionTest.GetServerParameters (ctx, filter);
		}
	}

	class ClientParameterAttribute : TestParameterAttribute, ITestParameterSource<ClientParameters>
	{
		public ClientParameterAttribute ()
			: base (null, TestFlags.Browsable)
		{
		}

		public IEnumerable<ClientParameters> GetParameters (TestContext ctx, string filter)
		{
			return SimpleConnectionTest.GetClientParameters (ctx, filter);
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

		public static IEnumerable<ServerParameters> GetServerParameters (TestContext ctx, string filter)
		{
			yield return new ServerParameters ("simple", ResourceManager.SelfSignedServerCertificate);
			yield break;
		}

		public static IEnumerable<ClientParameters> GetClientParameters (TestContext ctx, string filter)
		{
			yield return new ClientParameters ("simple") { VerifyPeerCertificate = false };
		}

		[AsyncTest]
		public async Task TestConnection (TestContext ctx,
			[ServerParameter] ServerParameters serverParameters,
			[ClientParameter] ClientParameters clientParameters,
			[ServerTestHost] IServerTestHost server,
			[ClientTestHost] IClientTestHost client)
		{
			ctx.LogMessage ("TEST CONNECTION: {0} {1} {2} {3}", serverParameters, clientParameters, server, client);
			await Task.Delay (10000);
		}

	}
}

