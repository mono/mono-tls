using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.WebTests.ConnectionFramework;

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

		public async Task WaitForConnection ()
		{
			await Connection.WaitForConnection ();
		}

		public async Task Run ()
		{
			await WaitForConnection ();
			var wrapper = new StreamWrapper (Connection.Stream);
			await MainLoop (wrapper);
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

