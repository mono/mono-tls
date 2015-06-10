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

	/*
	 * Test Parameters are resolved when the Test Suite is loaded.
	 * 
	 * Each value returned by ITestParameterSource<T> must have a unique ITestParameter.Value, which is a stringified
	 * representation that will be used during serialization and displayed in the UI.
	 * 
	 * The class that implements ITestParameterSource<T> may be instantiated multiple times and GetParameters() may also
	 * be called multiple times.  Returned values will be identified by their ITestParameter.Value identifier and returned
	 * objects from different invocations with the same identifier will be assumed to be identical.
	 * 
	 * You may choose to ignore 'filter' - if you use it, then you must ignore any unknown filter values and treat theam as
	 * if 'null' has been used.
	 * 
	 * The order in which multiple ITestParameterSource<T>'s are invoked can not be guaranteed - on the provided TestContext,
	 * only CurrentCategory and IsEnabled(TestFeature) may be used.
	 * 
	 * It is very important not to store any kind of state in these attribute classes.
	 * 
	 * If any consumer of these test parameters wishes to modify the returned objects, then these must implement
	 * Xamarin.AsyncTests.ICloneable to provide a deep copy.  GetParameters() may or may not be re-invoked on subsequent
	 * test runs, so modifying the returned object without using ICloneable will ask for trouble.
	 * 
	 */

	class MonoConnectionParameterAttribute : TestParameterAttribute, ITestParameterSource<MonoClientAndServerParameters>
	{
		public ICertificateValidator AcceptAll {
			get;
			private set;
		}

		public ICertificateValidator AcceptFromCA {
			get;
			private set;
		}

		public ProtocolVersions? IncludeProtocols {
			get; set;
		}

		public MonoConnectionParameterAttribute (string filter = null)
			: base (filter)
		{
			var provider = DependencyInjector.Get<ICertificateProvider> ();
			AcceptAll = provider.AcceptAll ();
			AcceptFromCA = provider.AcceptFromCA (ResourceManager.LocalCACertificate);
		}

		public MonoConnectionParameterAttribute (ProtocolVersions protocols, string filter = null)
			: this (filter)
		{
			IncludeProtocols = protocols;
			var provider = DependencyInjector.Get<ICertificateProvider> ();
			AcceptAll = provider.AcceptAll ();
			AcceptFromCA = provider.AcceptFromCA (ResourceManager.LocalCACertificate);
		}

		public IEnumerable<MonoClientAndServerParameters> GetParameters (TestContext ctx, string filter)
		{
			yield return new MonoClientAndServerParameters ("simple", ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAll
			};
			yield return new MonoClientAndServerParameters ("check-cipher", ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAll, ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			};
			yield return new MonoClientAndServerParameters ("verify-certificate", ResourceManager.ServerCertificateFromCA) {
				ClientCertificateValidator = AcceptFromCA, ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			};

			if (IncludeProtocols != null) {
				if ((IncludeProtocols & ProtocolVersions.Tls10) != ProtocolVersions.None) {
					yield return new MonoClientAndServerParameters ("simple-tls10", ResourceManager.SelfSignedServerCertificate) {
						ClientCertificateValidator = AcceptAll, ProtocolVersion = ProtocolVersions.Tls10,
						ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA
					};
				}

				if ((IncludeProtocols & ProtocolVersions.Tls11) != ProtocolVersions.None) {
					yield return new MonoClientAndServerParameters ("simple-tls11", ResourceManager.SelfSignedServerCertificate) {
						ClientCertificateValidator = AcceptAll, ProtocolVersion = ProtocolVersions.Tls11,
						ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA
					};
				}

				if ((IncludeProtocols & ProtocolVersions.Tls12) != ProtocolVersions.None) {
					yield return new MonoClientAndServerParameters ("simple-tls12", ResourceManager.SelfSignedServerCertificate) {
						ClientCertificateValidator = AcceptAll, ProtocolVersion = ProtocolVersions.Tls12,
						ExpectedCipher = CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
					};
				}
			}
		}
	}

	[Work]
	[AsyncTestFixture]
	public class MonoConnectionTest
	{
		[AsyncTest]
		public async Task TestConnection (TestContext ctx, CancellationToken cancellationToken,
			[ClientAndServerType (Identifier = "ConnectionType", ProviderFlags = ConnectionProviderFlags.SupportsMonoExtensions | ConnectionProviderFlags.CanSelectCiphers)]
			ClientAndServerType connectionType,
			[MonoConnectionParameter (ProtocolVersions.Tls10 | ProtocolVersions.Tls11 | ProtocolVersions.Tls12)]
			MonoClientAndServerParameters parameters,
			[MonoClientAndServer] MonoClientAndServer connection)
		{
			var handler = ClientAndServerHandlerFactory.HandshakeAndDone.Create (connection);
			await handler.WaitForConnection (ctx, cancellationToken);

			if (parameters.ExpectedCipher != null) {
				ctx.Assert (connection.Client.SupportsConnectionInfo, "client supports connection info");
				ctx.Assert (connection.Server.SupportsConnectionInfo, "server supports connection info");

				var clientInfo = connection.Client.GetConnectionInfo ();
				var serverInfo = connection.Server.GetConnectionInfo ();

				if (ctx.Expect (clientInfo, Is.Not.Null, "client connection info"))
					ctx.Expect (clientInfo.CipherCode, Is.EqualTo (parameters.ExpectedCipher.Value), "client cipher");
				if (ctx.Expect (serverInfo, Is.Not.Null, "server connection info"))
					ctx.Expect (serverInfo.CipherCode, Is.EqualTo (parameters.ExpectedCipher.Value), "server cipher");
			}

			if (parameters.ProtocolVersion != null) {
				ctx.Expect (connection.Client.ProtocolVersion, Is.EqualTo (parameters.ProtocolVersion), "client protocol version");
				ctx.Expect (connection.Server.ProtocolVersion, Is.EqualTo (parameters.ProtocolVersion), "server protocol version");
			}

			await handler.Run (ctx, cancellationToken);
		}
	}
}

