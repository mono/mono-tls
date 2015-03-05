using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class ClientAndServerHandler : IConnectionHandler
	{
		public IServer Server {
			get;
			private set;
		}

		public IClient Client {
			get;
			private set;
		}

		public ClientAndServerHandler (IServer server, IClient client)
		{
			Server = server;
			Client = client;
		}

		public bool SupportsCleanShutdown {
			get { return Server.SupportsCleanShutdown && Client.SupportsCleanShutdown; }
		}

		public Task Run ()
		{
			var serverWrapper = new StreamWrapper (Server.Stream);
			var clientWrapper = new StreamWrapper (Client.Stream);
			return MainLoop (serverWrapper, clientWrapper);
		}

		protected abstract Task MainLoop (ILineBasedStream serverStream, ILineBasedStream clientStream);

		public async Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply)
		{
			var clientShutdown = Client.Shutdown (attemptCleanShutdown, waitForReply);
			var serverShutdown = Server.Shutdown (attemptCleanShutdown, waitForReply);
			await Task.WhenAll (clientShutdown, serverShutdown);
			return clientShutdown.Result && serverShutdown.Result;
		}

		public void Close ()
		{
			Client.Dispose ();
			Server.Dispose ();
		}
	}
}

