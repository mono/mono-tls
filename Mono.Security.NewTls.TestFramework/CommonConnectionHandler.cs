using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class CommonConnectionHandler : IConnectionHandler
	{
		public ICommonConnection Connection {
			get;
			private set;
		}

		public CommonConnectionHandler (ICommonConnection connection)
		{
			Connection = connection;
		}

		public bool SupportsCleanShutdown {
			get { return Connection.SupportsCleanShutdown; }
		}

		public Task Run ()
		{
			var wrapper = new StreamWrapper (Connection.Stream);
			return MainLoop (wrapper);
		}

		protected abstract Task MainLoop (ILineBasedStream stream);

		public Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply)
		{
			return Connection.Shutdown (attemptCleanShutdown, waitForReply);
		}

		public void Close ()
		{
			Connection.Dispose ();
		}
	}
}

