using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class ConnectionHandler
	{
		public abstract bool SupportsCleanShutdown {
			get;
		}

		public abstract Task Run ();

		public abstract Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply);

		public abstract void Close ();
	}
}

