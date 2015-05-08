//
// MonoTestFeatures.cs
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
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFeatures
{
	using TestFramework;

	public static class MonoTestFeatures
	{
		static readonly MonoConnectionProviderFactory Factory;
		static readonly Constraint isProviderSupported;
		static readonly Constraint isMonoProviderSupported;

		static MonoTestFeatures ()
		{
			Factory = DependencyInjector.Get<MonoConnectionProviderFactory> ();
			isProviderSupported = new IsSupportedConstraint<ConnectionProviderType> (f => Factory.IsSupported (f));
			isMonoProviderSupported = new IsSupportedConstraint<ConnectionProviderType> (f => Factory.IsMonoSupported (f));
		}

		public static Constraint IsProviderSupported {
			get { return isProviderSupported; }
		}

		public static Constraint IsMonoProviderSupported {
			get { return isMonoProviderSupported; }
		}

		public static ClientParameters GetClientParameters (TestContext ctx, bool requireMonoExtensions)
		{
			ClientParameters clientParameters;
			MonoClientParameters monoClientParameters;
			ClientAndServerParameters clientAndServerParameters;
			MonoClientAndServerParameters monoClientAndServerParameters;

			if (ctx.TryGetParameter<MonoClientParameters> (out monoClientParameters)) {
				clientParameters = monoClientParameters;	
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ClientParameters> (out clientParameters)) {
				;
			} else if (ctx.TryGetParameter<MonoClientAndServerParameters> (out monoClientAndServerParameters)) {
				clientAndServerParameters = monoClientAndServerParameters;
				clientParameters = monoClientParameters = monoClientAndServerParameters.MonoClientParameters;
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ClientAndServerParameters> (out clientAndServerParameters)) {
				clientParameters = clientAndServerParameters.ClientParameters;
			} else {
				ctx.AssertFail ("Missing '{0}' property.", requireMonoExtensions ? "MonoClientParameters" : "ClientParameters");
				return null;
			}

			if (monoClientParameters != null) {
				CipherSuiteCode requestedCipher;
				if (ctx.TryGetParameter<CipherSuiteCode> (out requestedCipher, "ClientCipher")) {
					// we receive a deep-cloned copy, so we can modify it here.
					monoClientParameters.ClientCiphers = new CipherSuiteCode[] { requestedCipher };
					monoClientParameters.ExpectedCipher = requestedCipher;
				}
			}

			return clientParameters;
		}

		public static ServerParameters GetServerParameters (TestContext ctx, bool requireMonoExtensions)
		{
			ServerParameters serverParameters;
			MonoServerParameters monoServerParameters;
			ClientAndServerParameters clientAndServerParameters;
			MonoClientAndServerParameters monoClientAndServerParameters;

			if (ctx.TryGetParameter<MonoServerParameters> (out monoServerParameters)) {
				serverParameters = monoServerParameters;	
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ServerParameters> (out serverParameters)) {
				;
			} else if (ctx.TryGetParameter<MonoClientAndServerParameters> (out monoClientAndServerParameters)) {
				clientAndServerParameters = monoClientAndServerParameters;
				serverParameters = monoServerParameters = monoClientAndServerParameters.MonoServerParameters;
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ClientAndServerParameters> (out clientAndServerParameters)) {
				serverParameters = clientAndServerParameters.ServerParameters;
			} else {
				ctx.AssertFail ("Missing '{0}' property.", requireMonoExtensions ? "MonoServerParameters" : "ServerParameters");
				return null;
			}

			if (monoServerParameters != null) {
				CipherSuiteCode requestedCipher;
				if (ctx.TryGetParameter<CipherSuiteCode> (out requestedCipher, "ServerCipher")) {
					// we receive a deep-cloned copy, so we can modify it here.
					monoServerParameters.ServerCiphers = new CipherSuiteCode[] { requestedCipher };
					monoServerParameters.ExpectedCipher = requestedCipher;
				}
			}

			return serverParameters;
		}

		public static ConnectionProviderType GetClientType (TestContext ctx)
		{
			ConnectionProviderType type;
			if (ctx.TryGetParameter<ConnectionProviderType> (out type, "ClientType"))
				return type;
			return ctx.GetParameter<ClientAndServerType> ().Client;
		}

		public static ConnectionProviderType GetServerType (TestContext ctx)
		{
			ConnectionProviderType type;
			if (ctx.TryGetParameter<ConnectionProviderType> (out type, "ServerType"))
				return type;
			return ctx.GetParameter<ClientAndServerType> ().Server;
		}

		public static IClient CreateClient (TestContext ctx)
		{
			var providerType = GetClientType (ctx);
			ctx.Assert (providerType, IsProviderSupported);
			var provider = Factory.GetProvider (providerType);

			var parameters = GetClientParameters (ctx, false);
			return provider.CreateClient (parameters);
		}

		public static IMonoClient CreateMonoClient (TestContext ctx, bool requireMonoExtensions)
		{
			var providerType = GetClientType (ctx);
			ctx.Assert (providerType, IsProviderSupported);
			var provider = Factory.GetMonoProvider (providerType);

			var parameters = GetClientParameters (ctx, requireMonoExtensions);
			return provider.CreateMonoClient (parameters);
		}

		public static IServer CreateServer (TestContext ctx)
		{
			var providerType = GetServerType (ctx);
			ctx.Assert (providerType, IsMonoProviderSupported);
			var provider = Factory.GetProvider (providerType);

			var parameters = GetServerParameters (ctx, false);
			return provider.CreateServer (parameters);
		}

		public static IMonoServer CreateMonoServer (TestContext ctx, bool requireMonoExtensions)
		{
			var providerType = GetServerType (ctx);
			ctx.Assert (providerType, IsMonoProviderSupported);
			var provider = Factory.GetMonoProvider (providerType);

			var parameters = GetServerParameters (ctx, requireMonoExtensions);
			return provider.CreateMonoServer (parameters);
		}

		public static ClientAndServer CreateClientAndServer (TestContext ctx)
		{
			var server = CreateServer (ctx);
			var client = CreateClient (ctx);
			return new ClientAndServer (server, client);
		}

		public static MonoClientAndServer CreateMonoClientAndServer (TestContext ctx, bool requireMonoExtensions)
		{
			var server = CreateMonoServer (ctx, requireMonoExtensions);
			var client = CreateMonoClient (ctx, requireMonoExtensions);
			return new MonoClientAndServer (server, client);
		}
	}
}

