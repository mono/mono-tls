using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class CommonConnectionHandler : ConnectionHandler
	{
		public ICommonConnection Connection {
			get;
			private set;
		}

		public CommonConnectionHandler (ICommonConnection connection)
		{
			Connection = connection;
		}

		public override bool SupportsCleanShutdown {
			get { return Connection.SupportsCleanShutdown; }
		}

		public override Task Run ()
		{
			var wrapper = new StreamWrapper (Connection.Stream);
			return MainLoop (wrapper);
		}

		protected abstract Task MainLoop (ILineBasedStream stream);

		public override Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply)
		{
			return Connection.Shutdown (attemptCleanShutdown, waitForReply);
		}

		public override void Close ()
		{
			Connection.Dispose ();
		}
	}
}

