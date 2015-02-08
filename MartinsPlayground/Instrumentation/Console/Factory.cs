using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;
	using Resources;

	public static class Factory
	{
		static ServerFactory openSslServer;
		static ServerFactory dotNetServer;
		static ClientFactory openSslClient;
		static ClientFactory dotNetClient;
		static ServerFactory monoServer;
		static ClientFactory monoClient;

		static Factory ()
		{
			openSslServer = new OpenSslServerFactory (new IPEndPoint (IPAddress.Loopback, 4433));
			dotNetServer = new DotNetServerFactory (new IPEndPoint (IPAddress.Any, 4433));
			openSslClient = new OpenSslClientFactory (new IPEndPoint (IPAddress.Loopback, 4433));
			dotNetClient = new DotNetClientFactory (new IPEndPoint (IPAddress.Loopback , 4433));
			monoServer = new MonoServerFactory (new IPEndPoint (IPAddress.Any, 4433));
			monoClient = new MonoClientFactory (new IPEndPoint (IPAddress.Loopback , 4433));
		}

		public static ServerFactory OpenSslServer {
			get { return openSslServer; }
		}

		public static ServerFactory DotNetServer {
			get { return dotNetServer; }
		}

		public static ClientFactory OpenSslClient {
			get { return openSslClient; }
		}

		public static ClientFactory DotNetClient {
			get { return dotNetClient; }
		}

		public static ServerFactory MonoServer {
			get { return monoServer; }
		}

		public static ClientFactory MonoClient {
			get { return monoClient; }
		}

		class OpenSslServerFactory : ServerFactory
		{
			public IPEndPoint EndPoint {
				get;
				private set;
			}

			public override bool IsMono {
				get { return false; }
			}

			public OpenSslServerFactory (IPEndPoint endpoint)
			{
				EndPoint = endpoint;
			}

			public override IServer CreateServer (IServerParameters parameters)
			{
				var certificate = ResourceManager.DefaultServerCertificate;
				return new OpenSslServer (this, EndPoint, certificate, parameters);
			}

			public override ConnectionType ConnectionType {
				get { return ConnectionType.OpenSslServer; }
			}

			public override bool HasConnectionInfo {
				get { return true; }
			}

			public override bool SupportsCleanShutdown {
				get { return true; }
			}

			public override bool CanSelectCiphers {
				get { return true; }
			}

			public override string ToString ()
			{
				return "[OpenSslServer]";
			}
		}

		class OpenSslClientFactory : ClientFactory
		{
			public IPEndPoint EndPoint {
				get;
				private set;
			}

			public override bool IsMono {
				get { return false; }
			}

			public OpenSslClientFactory (IPEndPoint endpoint)
			{
				EndPoint = endpoint;
			}

			public override IClient CreateClient (IClientParameters parameters)
			{
				return new OpenSslClient (this, EndPoint, parameters);
			}

			public override ConnectionType ConnectionType {
				get { return ConnectionType.OpenSslClient; }
			}

			public override bool HasConnectionInfo {
				get { return true; }
			}

			public override bool SupportsCleanShutdown {
				get { return true; }
			}

			public override bool CanSelectCiphers {
				get { return true; }
			}

			public override string ToString ()
			{
				return "[OpenSslClient]";
			}
		}

		class DotNetClientFactory : ClientFactory
		{
			public IPEndPoint EndPoint {
				get;
				private set;
			}

			public override bool IsMono {
				get { return false; }
			}

			public DotNetClientFactory (IPEndPoint endpoint)
			{
				EndPoint = endpoint;
			}

			public override IClient CreateClient (IClientParameters parameters)
			{
				return new DotNetClient (this, EndPoint, parameters);
			}

			public override ConnectionType ConnectionType {
				get { return ConnectionType.DotNetClient; }
			}

			public override bool HasConnectionInfo {
				get { return false; }
			}

			public override bool SupportsCleanShutdown {
				get { return false; }
			}

			public override bool CanSelectCiphers {
				get { return false; }
			}

			public override string ToString ()
			{
				return "[DotNetClient]";
			}
		}

		class DotNetServerFactory : ServerFactory
		{
			public IPEndPoint EndPoint {
				get;
				private set;
			}

			public override bool IsMono {
				get { return false; }
			}

			public DotNetServerFactory (IPEndPoint endpoint)
			{
				EndPoint = endpoint;
			}

			public override IServer CreateServer (IServerParameters parameters)
			{
				var certificate = ResourceManager.DefaultServerCertificate;
				return new DotNetServer (this, EndPoint, certificate, parameters);
			}

			public override ConnectionType ConnectionType {
				get { return ConnectionType.DotNetServer; }
			}

			public override bool HasConnectionInfo {
				get { return false; }
			}

			public override bool SupportsCleanShutdown {
				get { return false; }
			}

			public override bool CanSelectCiphers {
				get { return false; }
			}

			public override string ToString ()
			{
				return "[DotNetServer]";
			}
		}

		class MonoClientFactory : ClientFactory
		{
			public IPEndPoint EndPoint {
				get;
				private set;
			}

			public override bool IsMono {
				get { return true; }
			}

			public MonoClientFactory (IPEndPoint endpoint)
			{
				EndPoint = endpoint;
			}

			public override IClient CreateClient (IClientParameters parameters)
			{
				return new MonoClient (this, EndPoint, parameters);
			}

			public override ConnectionType ConnectionType {
				get { return ConnectionType.MonoClient; }
			}

			public override bool HasConnectionInfo {
				get { return true; }
			}

			public override bool SupportsCleanShutdown {
				get { return true; }
			}

			public override bool CanSelectCiphers {
				get { return true; }
			}

			public override string ToString ()
			{
				return "[MonoClient]";
			}
		}

		class MonoServerFactory : ServerFactory
		{
			public IPEndPoint EndPoint {
				get;
				private set;
			}

			public override bool IsMono {
				get { return true; }
			}

			public MonoServerFactory (IPEndPoint endpoint)
			{
				EndPoint = endpoint;
			}

			public override IServer CreateServer (IServerParameters parameters)
			{
				var certificate = ResourceManager.DefaultServerCertificate;
				return new MonoServer (this, EndPoint, certificate, parameters);
			}

			public override ConnectionType ConnectionType {
				get { return ConnectionType.MonoServer; }
			}

			public override bool HasConnectionInfo {
				get { return true; }
			}

			public override bool SupportsCleanShutdown {
				get { return true; }
			}

			public override bool CanSelectCiphers {
				get { return true; }
			}

			public override string ToString ()
			{
				return "[MonoServer]";
			}
		}
	}
}

