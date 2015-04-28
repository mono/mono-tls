//
// ConnectionTest.cs
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
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	public class MonoServerTestHostAttribute : TestHostAttribute, ITestHost<IMonoServer>
	{
		public MonoServerTestHostAttribute ()
			: base (typeof (MonoServerTestHostAttribute))
		{
		}

		public IMonoServer CreateInstance (TestContext ctx)
		{
			var providerType = ctx.GetParameter<ConnectionProviderType> ("ServerType");
			var parameters = ctx.GetParameter<MonoClientAndServerParameters> ();

			CipherSuiteCode requestedCipher;
			if (ctx.TryGetParameter<CipherSuiteCode> (out requestedCipher, "ServerCipher")) {
				// we receive a deep-cloned copy, so we can modify it here.
				parameters.ServerCiphers = new CipherSuiteCode[] { requestedCipher };
				parameters.ExpectedCipher = requestedCipher;
			}

			var factory = DependencyInjector.Get<IMonoConnectionProviderFactory> ();
			var provider = factory.GetMonoProvider (providerType);
			return provider.CreateMonoServer (parameters);
		}
	}

	public class MonoClientTestHostAttribute : TestHostAttribute, ITestHost<IMonoClient>
	{
		public MonoClientTestHostAttribute ()
			: base (typeof (MonoClientTestHostAttribute))
		{
		}

		public IMonoClient CreateInstance (TestContext ctx)
		{
			var providerType = ctx.GetParameter<ConnectionProviderType> ("ClientType");
			var parameters = ctx.GetParameter<MonoClientAndServerParameters> ();

			CipherSuiteCode requestedCipher;
			if (ctx.TryGetParameter<CipherSuiteCode> (out requestedCipher, "ClientCipher")) {
				// we receive a deep-cloned copy, so we can modify it here.
				parameters.ClientCiphers = new CipherSuiteCode[] { requestedCipher };
				parameters.ExpectedCipher = requestedCipher;
			}


			var factory = DependencyInjector.Get<IMonoConnectionProviderFactory> ();
			var provider = factory.GetMonoProvider (providerType);
			return provider.CreateMonoClient (parameters);
		}
	}
}

