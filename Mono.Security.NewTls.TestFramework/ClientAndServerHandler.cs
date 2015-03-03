using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class ClientAndServerHandler : ConnectionHandler
	{
		new public IClientAndServer Connection {
			get { return (IClientAndServer)base.Connection; }
		}

		public ClientAndServerHandler (IClientAndServer connection)
			: base (connection)
		{
		}

		public override Task Run ()
		{
			var serverWrapper = new StreamWrapper (Connection.Server.Stream);
			var clientWrapper = new StreamWrapper (Connection.Client.Stream);
			return MainLoop (serverWrapper, clientWrapper);
		}

		protected abstract Task MainLoop (ILineBasedStream serverStream, ILineBasedStream clientStream);
	}
}

