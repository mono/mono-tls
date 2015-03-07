﻿//
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
		public IEnumerable<CipherSuiteCode> GetParameters (TestContext ctx, string filter)
		{
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
			[ServerTestHost] IServer server,
			[SelectCipherSuite] CipherSuiteCode clientCipher,
			[ClientTestHost] IClient client)
		{
			ctx.LogMessage ("SELECT CLIENT CIPHERS: {0} {1} {2} {3}", clientCipher, parameters, server, client);

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
			[SelectCipherSuite] CipherSuiteCode serverCipher,
			[ServerTestHost] IServer server,
			[ClientTestHost] IClient client)
		{
			ctx.LogMessage ("SELECT SERVER CIPHERS: {0} {1} {2} {3}", serverCipher, parameters, server, client);

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
	}
}

