using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls.TestFramework;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class ConnectionFactory : IConnectionFactory
	{
		public abstract IConnection Create (IConnectionParameters parameters);

		public abstract ConnectionType ConnectionType {
			get;
		}

		public abstract bool HasConnectionInfo {
			get;
		}

		public abstract bool SupportsCleanShutdown {
			get;
		}

		public abstract bool CanSelectCiphers {
			get;
		}

		public Task<IConnection> Start (IConnectionParameters parameters)
		{
			var tcs = new TaskCompletionSource<IConnection> ();
			ThreadPool.QueueUserWorkItem (_ => {
				IConnection connection = null;
				try {
					connection = Create (parameters);
					connection.Start (null, CancellationToken.None).Wait ();
					connection.WaitForConnection ().Wait ();
					tcs.SetResult (connection);
				} catch (Exception ex) {
					if (connection != null)
						connection.Dispose ();
					tcs.SetException (ex);
				}
			});
			return tcs.Task;
		}

		public override string ToString ()
		{
			return string.Format ("[{0}]", GetType ().Name);
		}
	}

	public abstract class ServerFactory : ConnectionFactory
	{
		public abstract bool IsMono {
			get;
		}

		public abstract IServer CreateServer (IServerParameters parameters);

		public override IConnection Create (IConnectionParameters parameters)
		{
			return CreateServer ((IServerParameters)parameters);
		}
	}

	public abstract class ClientFactory : ConnectionFactory
	{
		public abstract bool IsMono {
			get;
		}

		public abstract IClient CreateClient (IClientParameters parameters);

		public override IConnection Create (IConnectionParameters parameters)
		{
			return CreateClient ((IClientParameters)parameters);
		}
	}

	public class ClientAndServerFactory : ConnectionFactory
	{
		public ServerFactory ServerFactory {
			get;
			private set;
		}

		public ClientFactory ClientFactory {
			get;
			private set;
		}

		public ClientAndServerFactory (ServerFactory serverFactory, ClientFactory clientFactory)
		{
			ServerFactory = serverFactory;
			ClientFactory = clientFactory;
		}

		public override IConnection Create (IConnectionParameters parameters)
		{
			return CreateClientAndServer ((IClientAndServerParameters)parameters);
		}

		[Obsolete]
		public ClientAndServer CreateClientAndServer (IClientAndServerParameters parameters)
		{
			if (parameters == null)
				parameters = new ClientAndServerParameters (null, null);
			return new ClientAndServer (ServerFactory.CreateServer (parameters), ClientFactory.CreateClient (parameters), parameters);
		}

		public override ConnectionType ConnectionType {
			get { return ServerFactory.ConnectionType | ClientFactory.ConnectionType; }
		}

		public bool Matches (ConnectionType connectionType)
		{
			if ((ServerFactory.ConnectionType & connectionType) == 0)
				return false;
			if ((ClientFactory.ConnectionType & connectionType) == 0)
				return false;
			return true;
		}

		public override bool HasConnectionInfo {
			get { return ServerFactory.HasConnectionInfo && ClientFactory.HasConnectionInfo; }
		}

		public override bool SupportsCleanShutdown {
			get { return ServerFactory.SupportsCleanShutdown && ClientFactory.SupportsCleanShutdown; }
		}

		public override bool CanSelectCiphers {
			get { return ServerFactory.CanSelectCiphers && ClientFactory.CanSelectCiphers; }
		}

		public override string ToString ()
		{
			return string.Format ("{0}*{1}", ServerFactory, ClientFactory);
		}
	}
}

