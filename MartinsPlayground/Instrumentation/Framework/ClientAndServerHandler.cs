using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class ClientAndServerHandler : ConnectionHandler
	{
		new public ClientAndServer Connection {
			get { return (ClientAndServer)base.Connection; }
		}

		public ClientAndServerHandler (ClientAndServer connection)
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

