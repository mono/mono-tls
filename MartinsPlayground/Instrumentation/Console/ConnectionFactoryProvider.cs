using System;
using System.Linq;
using System.Reflection;
using System.Collections;
using System.Collections.Generic;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	public static class ConnectionFactoryProvider
	{
		public static ClientFactory GetClientFactory (string name)
		{
			if (name == "openssl")
				return Factory.OpenSslClient;
			else if (name == "dotnet")
				return Factory.DotNetClient;
			else if (name == "mono")
				return Factory.MonoClient;
			else
				throw new InvalidOperationException ();
		}

		public static ServerFactory GetServerFactory (string name)
		{
			if (name == "openssl")
				return Factory.OpenSslServer;
			else if (name == "dotnet")
				return Factory.DotNetServer;
			else if (name == "mono")
				return Factory.MonoServer;
			else
				throw new InvalidOperationException ();
		}

		static void AddClientFactories (List<ClientFactory> list, string names)
		{
			foreach (var name in names.Split (','))
				list.Add (GetClientFactory (name));
		}

		static void AddServerFactories (List<ServerFactory> list, string names)
		{
			foreach (var name in names.Split (','))
				list.Add (GetServerFactory (name));
		}

		public static IConnectionFactoryProvider GetClientAndServer (string clientArg, string serverArg)
		{
			var clientFactories = new List<ClientFactory> ();
			var serverFactories = new List<ServerFactory> ();

			if (clientArg == null)
				clientArg = "all";
			if (serverArg == null)
				serverArg = "all";

			if (clientArg.Equals ("all")) {
				clientFactories.Add (Factory.MonoClient);
				clientFactories.Add (Factory.OpenSslClient);
			} else {
				AddClientFactories (clientFactories, clientArg);
			}

			if (serverArg.Equals ("all")) {
				serverFactories.Add (Factory.MonoServer);
				serverFactories.Add (Factory.OpenSslServer);
			} else if (serverArg != null) {
				AddServerFactories (serverFactories, serverArg);
			}

			var factories = new List<ClientAndServerFactory> ();
			foreach (var server in serverFactories) {
				foreach (var client in clientFactories) {
					factories.Add (new ClientAndServerFactory (server, client));
				}
			}

			return new MyFactoryProvider (factories);
		}

		class MyFactoryProvider : IConnectionFactoryProvider
		{
			IList<ClientAndServerFactory> factories;

			public MyFactoryProvider (IList<ClientAndServerFactory> factories)
			{
				this.factories = factories;
			}

			public IEnumerable<ConnectionFactory> Factories {
				get { return factories; }
			}

			Type ITestParameterProvider.Type {
				get { return typeof(ClientAndServerFactory); }
			}

			string ITestParameterProvider.Name {
				get { return null; }
			}

			public IEnumerable GetParameters (Type fixtureType)
			{
				var attrs = fixtureType.GetCustomAttributes<ConnectionFactoryParametersAttribute> ().ToArray ();

				foreach (var factory in factories) {
					if (attrs.Length == 0)
						yield return factory;

					foreach (var attr in attrs) {
						if (factory.Matches (attr.ConnectionType))
							yield return factory;
					}
				}
			}
		}
	}
}

