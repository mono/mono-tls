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
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestRunners;

namespace Mono.Security.NewTls.TestFeatures
{
	using TestFramework;

	public static class MonoTestFeatures
	{
		static readonly ConnectionProviderFactory Factory;
		static readonly MonoConnectionProviderFactory MonoFactory;
		static readonly Constraint isProviderSupported;
		static readonly Constraint isMonoProviderSupported;
		static readonly Constraint isInstrumentationSupported;

		static MonoTestFeatures ()
		{
			if (DependencyInjector.TryGet<MonoConnectionProviderFactory> (out MonoFactory))
				Factory = MonoFactory;
			else
				Factory = DependencyInjector.Get<ConnectionProviderFactory> ();
			isProviderSupported = new IsSupportedConstraint<ConnectionProviderType> (f => Factory.IsSupported (f));
			isMonoProviderSupported = new IsSupportedConstraint<ConnectionProviderType> (f => MonoFactory != null && MonoFactory.IsMonoSupported (f));
			isInstrumentationSupported = new IsSupportedConstraint<ConnectionProviderType> (f => MonoFactory != null && MonoFactory.IsInstrumentationSupported (f));
		}

		static void RequireMono ()
		{
			if (MonoFactory == null)
				throw new NotSupportedException ();
		}

		public static Constraint IsProviderSupported {
			get { return isProviderSupported; }
		}

		public static Constraint IsMonoProviderSupported {
			get { return isMonoProviderSupported; }
		}

		public static Constraint IsInstrumentationSupported {
			get { return isInstrumentationSupported; }
		}

		public static ClientParameters GetClientParameters (TestContext ctx, bool requireMonoExtensions)
		{
			ClientAndServerParameters clientAndServerParameters = null;
			return GetClientParameters (ctx, requireMonoExtensions, ref clientAndServerParameters);
		}

		public static ClientParameters GetClientParameters (TestContext ctx, bool requireMonoExtensions, ref ClientAndServerParameters clientAndServerParameters)
		{
			ClientParameters clientParameters;
			MonoClientParameters monoClientParameters;
			MonoClientAndServerParameters monoClientAndServerParameters = clientAndServerParameters as MonoClientAndServerParameters;
			MonoClientAndServerTestType testType;

			if (monoClientAndServerParameters != null) {
				clientParameters = monoClientParameters = monoClientAndServerParameters.MonoClientParameters;
			} else if (!requireMonoExtensions && clientAndServerParameters != null) {
				clientParameters = clientAndServerParameters.ClientParameters;
				monoClientParameters = clientParameters as MonoClientParameters;
			} else if (ctx.TryGetParameter<MonoClientParameters> (out monoClientParameters)) {
				clientParameters = monoClientParameters;
				clientAndServerParameters = null;
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ClientParameters> (out clientParameters)) {
				clientAndServerParameters = null;
			} else if (ctx.TryGetParameter<MonoClientAndServerParameters> (out monoClientAndServerParameters)) {
				clientAndServerParameters = monoClientAndServerParameters;
				clientParameters = monoClientParameters = monoClientAndServerParameters.MonoClientParameters;
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ClientAndServerParameters> (out clientAndServerParameters)) {
				clientParameters = clientAndServerParameters.ClientParameters;
			} else if (ctx.TryGetParameter<MonoClientAndServerTestType> (out testType)) {
				monoClientAndServerParameters = MonoClientAndServerTestRunner.GetParameters (ctx, testType);
				clientAndServerParameters = monoClientAndServerParameters;
				clientParameters = monoClientParameters = monoClientAndServerParameters.MonoClientParameters;
			} else {
				ctx.AssertFail ("Missing '{0}' property.", requireMonoExtensions ? "MonoClientParameters" : "ClientParameters");
				clientAndServerParameters = null;
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
			ClientAndServerParameters clientAndServerParameters = null;
			return GetServerParameters (ctx, requireMonoExtensions, ref clientAndServerParameters);
		}

		public static ServerParameters GetServerParameters (TestContext ctx, bool requireMonoExtensions, ref ClientAndServerParameters clientAndServerParameters)
		{
			ServerParameters serverParameters;
			MonoServerParameters monoServerParameters;
			MonoClientAndServerParameters monoClientAndServerParameters = clientAndServerParameters as MonoClientAndServerParameters;
			MonoClientAndServerTestType testType;

			if (monoClientAndServerParameters != null) {
				serverParameters = monoServerParameters = monoClientAndServerParameters.MonoServerParameters;
			} else if (!requireMonoExtensions && clientAndServerParameters != null) {
				serverParameters = clientAndServerParameters.ServerParameters;
				monoServerParameters = serverParameters as MonoServerParameters;
			} else if (ctx.TryGetParameter<MonoServerParameters> (out monoServerParameters)) {
				serverParameters = monoServerParameters;
				clientAndServerParameters = null;
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ServerParameters> (out serverParameters)) {
				clientAndServerParameters = null;
			} else if (ctx.TryGetParameter<MonoClientAndServerParameters> (out monoClientAndServerParameters)) {
				clientAndServerParameters = monoClientAndServerParameters;
				serverParameters = monoServerParameters = monoClientAndServerParameters.MonoServerParameters;
			} else if (!requireMonoExtensions && ctx.TryGetParameter<ClientAndServerParameters> (out clientAndServerParameters)) {
				serverParameters = clientAndServerParameters.ServerParameters;
			} else if (ctx.TryGetParameter<MonoClientAndServerTestType> (out testType)) {
				monoClientAndServerParameters = MonoClientAndServerTestRunner.GetParameters (ctx, testType);
				clientAndServerParameters = monoClientAndServerParameters;
				serverParameters = monoServerParameters = monoClientAndServerParameters.MonoServerParameters;
			} else {
				ctx.AssertFail ("Missing '{0}' property.", requireMonoExtensions ? "MonoServerParameters" : "ServerParameters");
				clientAndServerParameters = null;
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
			RequireMono ();
			var providerType = GetClientType (ctx);
			ctx.Assert (providerType, IsMonoProviderSupported);
			var provider = MonoFactory.GetMonoProvider (providerType);

			var parameters = GetClientParameters (ctx, requireMonoExtensions);
			return provider.CreateMonoClient (parameters);
		}

		public static IServer CreateServer (TestContext ctx)
		{
			var providerType = GetServerType (ctx);
			ctx.Assert (providerType, IsProviderSupported);
			var provider = Factory.GetProvider (providerType);

			var parameters = GetServerParameters (ctx, false);
			return provider.CreateServer (parameters);
		}

		public static IMonoServer CreateMonoServer (TestContext ctx, bool requireMonoExtensions)
		{
			RequireMono ();
			var providerType = GetServerType (ctx);
			ctx.Assert (providerType, IsMonoProviderSupported);
			var provider = MonoFactory.GetMonoProvider (providerType);

			var parameters = GetServerParameters (ctx, requireMonoExtensions);
			return provider.CreateMonoServer (parameters);
		}

		public static ClientAndServer CreateClientAndServer (TestContext ctx)
		{
			var clientProviderType = GetClientType (ctx);
			ctx.Assert (clientProviderType, IsProviderSupported);
			var clientProvider = Factory.GetProvider (clientProviderType);

			var serverProviderType = GetServerType (ctx);
			ctx.Assert (serverProviderType, IsProviderSupported);
			var serverProvider = Factory.GetProvider (serverProviderType);

			ClientAndServerParameters clientAndServerParameters = null;
			var clientParameters = GetClientParameters (ctx, false, ref clientAndServerParameters);
			var serverParameters = GetServerParameters (ctx, false, ref clientAndServerParameters);

			if (clientAndServerParameters == null)
				clientAndServerParameters = new ClientAndServerParameters (clientParameters, serverParameters);

			var server = serverProvider.CreateServer (clientAndServerParameters.ServerParameters);
			var client = clientProvider.CreateClient (clientAndServerParameters.ClientParameters);
			return new ClientAndServer (server, client, clientAndServerParameters);
		}

		public static MonoClientAndServer CreateMonoClientAndServer (TestContext ctx, bool requireMonoExtensions)
		{
			RequireMono ();
			var clientProviderType = GetClientType (ctx);
			ctx.Assert (clientProviderType, IsMonoProviderSupported);
			var clientProvider = MonoFactory.GetMonoProvider (clientProviderType);

			var serverProviderType = GetServerType (ctx);
			ctx.Assert (serverProviderType, IsMonoProviderSupported);
			var serverProvider = MonoFactory.GetMonoProvider (serverProviderType);

			ClientAndServerParameters clientAndServerParameters = null;
			var clientParameters = GetClientParameters (ctx, true, ref clientAndServerParameters);
			var serverParameters = GetServerParameters (ctx, true, ref clientAndServerParameters);

			if (clientAndServerParameters == null)
				clientAndServerParameters = new MonoClientAndServerParameters (clientParameters, serverParameters);

			var server = serverProvider.CreateMonoServer (clientAndServerParameters.ServerParameters);
			var client = clientProvider.CreateMonoClient (clientAndServerParameters.ClientParameters);
			return new MonoClientAndServer (server, client, (MonoClientAndServerParameters)clientAndServerParameters);
		}

		public static MonoClientAndServerTestRunner CreateMonoClientAndServerTestRunner (TestContext ctx, bool requireMonoExtensions)
		{
			RequireMono ();
			var clientProviderType = GetClientType (ctx);
			ctx.Assert (clientProviderType, IsMonoProviderSupported);
			var clientProvider = MonoFactory.GetMonoProvider (clientProviderType);

			var serverProviderType = GetServerType (ctx);
			ctx.Assert (serverProviderType, IsMonoProviderSupported);
			var serverProvider = MonoFactory.GetMonoProvider (serverProviderType);

			ClientAndServerParameters clientAndServerParameters = null;
			var clientParameters = GetClientParameters (ctx, true, ref clientAndServerParameters);
			var serverParameters = GetServerParameters (ctx, true, ref clientAndServerParameters);

			if (clientAndServerParameters == null)
				clientAndServerParameters = new MonoClientAndServerParameters (clientParameters, serverParameters);

			ProtocolVersions protocolVersion;
			if (ctx.TryGetParameter<ProtocolVersions> (out protocolVersion))
				clientAndServerParameters.ProtocolVersion = protocolVersion;

			var server = serverProvider.CreateMonoServer (clientAndServerParameters.ServerParameters);
			var client = clientProvider.CreateMonoClient (clientAndServerParameters.ClientParameters);
			return new MonoClientAndServerTestRunner (server, client, (MonoClientAndServerParameters)clientAndServerParameters);
		}

		public static R CreateTestRunner<P,R> (TestContext ctx, MonoConnectionFlags flags, Func<IServer,IClient,P,MonoConnectionFlags,R> constructor)
			where P : ClientAndServerParameters
			where R : ClientAndServerTestRunner
		{
			var parameters = ctx.GetParameter<P> ();
			return CreateTestRunner (ctx, parameters, flags, constructor);
		}

		public static R CreateTestRunner<P,R> (TestContext ctx, P parameters, MonoConnectionFlags flags, Func<IServer,IClient,P,MonoConnectionFlags,R> constructor)
			where P : ClientAndServerParameters
			where R : ClientAndServerTestRunner
		{
			var clientProviderType = GetClientType (ctx);
			MonoConnectionProvider monoClientProvider;
			ConnectionProvider clientProvider;

			if ((flags & MonoConnectionFlags.ClientInstrumentation) != 0) {
				ctx.Assert (clientProviderType, IsInstrumentationSupported);
				clientProvider = monoClientProvider = MonoFactory.GetMonoProvider (clientProviderType);
			} else if ((flags & MonoConnectionFlags.RequiresMonoClient) != 0) {
				ctx.Assert (clientProviderType, IsMonoProviderSupported);
				clientProvider = monoClientProvider = MonoFactory.GetMonoProvider (clientProviderType);
			} else {
				clientProvider = Factory.GetProvider (clientProviderType);
				monoClientProvider = null;
			}

			var serverProviderType = GetServerType (ctx);
			MonoConnectionProvider monoServerProvider;
			ConnectionProvider serverProvider;

			if ((flags & MonoConnectionFlags.ServerInstrumentation) != 0) {
				ctx.Assert (serverProviderType, IsInstrumentationSupported);
				serverProvider = monoServerProvider = MonoFactory.GetMonoProvider (serverProviderType);
			} else if ((flags & MonoConnectionFlags.RequiresMonoServer) != 0) {
				ctx.Assert (serverProviderType, IsMonoProviderSupported);
				serverProvider = monoServerProvider = MonoFactory.GetMonoProvider (serverProviderType);
			} else {
				serverProvider = Factory.GetProvider (serverProviderType);
				monoServerProvider = null;
			}

			ProtocolVersions protocolVersion;
			if (ctx.TryGetParameter<ProtocolVersions> (out protocolVersion))
				parameters.ProtocolVersion = protocolVersion;

			if (serverProviderType == ConnectionProviderType.Manual) {
				string serverAddress;
				if (!ctx.Settings.TryGetValue ("ServerAddress", out serverAddress))
					throw new NotSupportedException ("Missing 'ServerAddress' setting.");

				var support = DependencyInjector.Get<IPortableEndPointSupport> ();
				parameters.EndPoint = support.ParseEndpoint (serverAddress, 443, true);
				flags |= MonoConnectionFlags.ManualServer;

				string serverHost;
				if (ctx.Settings.TryGetValue ("ServerHost", out serverHost))
					parameters.ClientParameters.TargetHost = serverHost;
			}

			if (clientProviderType == ConnectionProviderType.Manual) {
				flags |= MonoConnectionFlags.ManualClient;
			}

			if (parameters.EndPoint != null) {
				if (parameters.ClientParameters.EndPoint == null)
					parameters.ClientParameters.EndPoint = parameters.EndPoint;
				if (parameters.ServerParameters.EndPoint == null)
					parameters.ServerParameters.EndPoint = parameters.EndPoint;

				if (parameters.ClientParameters.TargetHost == null)
					parameters.ClientParameters.TargetHost = parameters.EndPoint.HostName;
			}

			IServer server;
			if (monoServerProvider != null)
				server = monoServerProvider.CreateMonoServer (parameters.ServerParameters);
			else
				server = serverProvider.CreateServer (parameters.ServerParameters);

			IClient client;
			if (monoClientProvider != null)
				client = monoClientProvider.CreateMonoClient (parameters.ClientParameters);
			else
				client = clientProvider.CreateClient (parameters.ClientParameters);

			return constructor (server, client, parameters, flags);
		}

		public static R CreateTestRunner<P,R> (TestContext ctx, Func<IServer,IClient,P,MonoConnectionFlags,R> constructor)
			where P : InstrumentationParameters
			where R : InstrumentationTestRunner
		{
			var parameters = ctx.GetParameter<P> ();
			var flags = InstrumentationTestRunner.GetConnectionFlags (ctx, parameters.Category);
			return CreateTestRunner (ctx, parameters, flags, constructor);
		}
	}
}

