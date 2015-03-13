//
// SelectCiphersTest.cs
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
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	class SelectCipherSuiteAttribute : TestParameterAttribute, ITestParameterSource<CipherSuiteCode>
	{
		public SelectCipherSuiteAttribute (string name)
		{
			Identifier = name;
		}

		public SelectCipherSuiteAttribute (string name, CipherSuiteCode code)
			: base (code.ToString ())
		{
			Identifier = name;
		}

		public IEnumerable<CipherSuiteCode> GetParameters (TestContext ctx, string filter)
		{
			if (filter != null) {
				CipherSuiteCode code;
				if (!Enum.TryParse<CipherSuiteCode> (filter, out code))
					ctx.AssertFail ("Invalid cipher code '{0}'.", filter);

				yield return code;
				yield break;
			}

			// Galois-Counter Cipher Suites.
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;

			// Galois-Counter with Legacy RSA Key Exchange.
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_GCM_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_GCM_SHA384;

			// Diffie-Hellman Cipher Suites
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA;

			// Legacy AES Cipher Suites
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA256;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_256_CBC_SHA;
			yield return CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA;
		}
	}

	[AsyncTestFixture]
	public class SelectCiphersTest
	{
		[NewTlsTestFeatures.SelectConnectionProvider ("connection-info:select-ciphers")]
		public ConnectionProviderType ServerType {
			get;
			private set;
		}

		[NewTlsTestFeatures.SelectConnectionProvider ("connection-info:select-ciphers")]
		public ConnectionProviderType ClientType {
			get;
			private set;
		}

		[AsyncTest]
		public async Task SelectClientCipher (TestContext ctx,
			[SimpleConnectionParameter ("simple")] ClientAndServerParameters parameters,
			[SelectCipherSuite ("ClientCipher")] CipherSuiteCode clientCipher,
			[ServerTestHost] IServer server, [ClientTestHost] IClient client)
		{
			ctx.Assert (clientCipher, Is.EqualTo (parameters.ExpectedCipher.Value), "expected cipher");

			var handler = ClientAndServerHandlerFactory.HandshakeAndDone.Create (server, client);
			await handler.WaitForConnection ();

			var serverInfo = server.GetConnectionInfo ();
			ctx.Assert (serverInfo, Is.Not.Null, "server info");
			ctx.Assert (serverInfo.CipherCode, Is.EqualTo (clientCipher), "server cipher code");

			var clientInfo = client.GetConnectionInfo ();
			ctx.Assert (clientInfo, Is.Not.Null, "client info");
			ctx.Assert (clientInfo.CipherCode, Is.EqualTo (clientCipher), "client cipher");

			await handler.Run ();
		}

		[AsyncTest]
		public async Task SelectServerCipher (TestContext ctx,
			[SimpleConnectionParameter ("simple")] ClientAndServerParameters parameters,
			[SelectCipherSuite ("ServerCipher")] CipherSuiteCode serverCipher,
			[ServerTestHost] IServer server, [ClientTestHost] IClient client)
		{
			ctx.Assert (serverCipher, Is.EqualTo (parameters.ExpectedCipher.Value), "expected cipher");

			var handler = ClientAndServerHandlerFactory.HandshakeAndDone.Create (server, client);
			await handler.WaitForConnection ();

			var serverInfo = server.GetConnectionInfo ();
			ctx.Assert (serverInfo, Is.Not.Null, "server info");
			ctx.Assert (serverInfo.CipherCode, Is.EqualTo (serverCipher), "server cipher code");

			var clientInfo = client.GetConnectionInfo ();
			ctx.Assert (clientInfo, Is.Not.Null, "client info");
			ctx.Assert (clientInfo.CipherCode, Is.EqualTo (serverCipher), "client cipher");

			await handler.Run ();
		}

		[Work]
		[AsyncTest]
		public async Task InvalidCipher (TestContext ctx,
			[SimpleConnectionParameter ("simple")] ClientAndServerParameters parameters,
			[SelectCipherSuite ("ServerCipher", CipherSuiteCode.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)] CipherSuiteCode serverCipher,
			[SelectCipherSuite ("ClientCipher", CipherSuiteCode.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256)] CipherSuiteCode clientCipher,
			[ServerTestHost] IServer server, [ClientTestHost] IClient client)
		{
			await ExpectAlert (ctx, server, client, AlertDescription.HandshakeFailure);
		}

		void ExpectAlert (TestContext ctx, Task t, AlertDescription expectedAlert, string message)
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

		async Task ExpectAlert (TestContext ctx, IServer server, IClient client, AlertDescription alert)
		{
			var serverTask = server.WaitForConnection ();
			var clientTask = client.WaitForConnection ();

			var t1 = clientTask.ContinueWith (t => ExpectAlert (ctx, t, alert, "client"));
			var t2 = serverTask.ContinueWith (t => ExpectAlert (ctx, t, alert, "server"));

			await Task.WhenAll (t1, t2);
		}
	}
}

