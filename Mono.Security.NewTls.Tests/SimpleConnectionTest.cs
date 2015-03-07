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

	class SimpleConnectionParameterAttribute : ConnectionParameterAttribute
	{
		public override IEnumerable<ClientAndServerParameters> GetParameters (TestContext ctx, string filter)
		{
			yield return new ClientAndServerParameters ("simple", ResourceManager.SelfSignedServerCertificate) {
				VerifyPeerCertificate = false
			};
			yield return new ClientAndServerParameters ("verify-certificate", ResourceManager.ServerCertificateFromCA) {
				VerifyPeerCertificate = true, TrustedCA = ResourceManager.LocalCACertificate
			};
			yield return new ClientAndServerParameters ("ask-for-certificate", ResourceManager.ServerCertificateFromCA) {
				VerifyPeerCertificate = true, TrustedCA = ResourceManager.LocalCACertificate,
				AskForClientCertificate = true
			};
			yield return new ClientAndServerParameters ("require-certificate", ResourceManager.ServerCertificateFromCA) {
				VerifyPeerCertificate = true, TrustedCA = ResourceManager.LocalCACertificate,
				RequireClientCertificate = true, ClientCertificate = ResourceManager.MonkeyCertificate
			};
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

		[AsyncTest]
		public async Task TestConnection (TestContext ctx,
			[SimpleConnectionParameter] ClientAndServerParameters parameters,
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

