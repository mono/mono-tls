//
// MartinTest.cs
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
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Features;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;
	using TestFeatures;

	class MartinTestParameterAttribute : TestParameterAttribute, ITestParameterSource<MonoClientAndServerParameters>
	{
		public ICertificateValidator AcceptAll {
			get;
			private set;
		}

		public ICertificateValidator AcceptFromCA {
			get;
			private set;
		}

		public MartinTestParameterAttribute (string filter = null)
			: base (filter)
		{
			var provider = DependencyInjector.Get<ICertificateProvider> ();
			AcceptAll = provider.AcceptAll ();
			AcceptFromCA = provider.AcceptFromCA (ResourceManager.LocalCACertificate);
		}

		public IEnumerable<MonoClientAndServerParameters> GetParameters (TestContext ctx, string filter)
		{
			yield return new MonoClientAndServerParameters ("martin", ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAll, ServerCertificateValidator = AcceptAll, ProtocolVersion = ProtocolVersions.Tls12,
				ClientCertificate = ResourceManager.MonkeyCertificate, ServerFlags = ServerFlags.RequireClientCertificate
			};
		}
	}

	[Martin]
	[AsyncTestFixture]
	public class MartinTest
	{
		[AsyncTest]
		public async Task TestClient (TestContext ctx, CancellationToken cancellationToken,
			[ConnectionProvider ("MonoWithNewTLS", Identifier = "ClientType")] ConnectionProviderType clientType,
			[ConnectionProvider ("OpenSsl", Identifier = "ServerType")] ConnectionProviderType serverType,
			[MartinTestParameter] MonoClientAndServerParameters parameters,
			[MonoClientAndServer] MonoClientAndServer connection)
		{
			var handler = ClientAndServerHandlerFactory.HandshakeAndDone.Create (connection);
			await handler.WaitForConnection (ctx, cancellationToken);

			ctx.Expect (connection.Client.ProtocolVersion, Is.EqualTo (parameters.ProtocolVersion), "client protocol version");
			ctx.Expect (connection.Server.ProtocolVersion, Is.EqualTo (parameters.ProtocolVersion), "server protocol version");

			await handler.Run (ctx, cancellationToken);
		}

		[Martin]
		[AsyncTest]
		public Task TestAllVersions (TestContext ctx, CancellationToken cancellationToken,
			[ClientAndServerType (Identifier = "ConnectionType", ProviderFlags = ConnectionProviderFlags.SupportsMonoExtensions | ConnectionProviderFlags.CanSelectCiphers)]
			ClientAndServerType connectionType,
			[ProtocolVersions (ProtocolVersions.Tls10)] ProtocolVersions protocolVersion,
			[MonoClientAndServerTestType (MonoClientAndServerTestType.RequestClientCertificate, AllVersions = true)] MonoClientAndServerTestType type,
			[MonoClientAndServerTestRunner] MonoClientAndServerTestRunner runner)
		{
			return runner.Run (ctx, cancellationToken);
		}
	}
}

