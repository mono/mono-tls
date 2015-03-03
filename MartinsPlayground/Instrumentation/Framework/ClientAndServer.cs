using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.NewTls;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	public class ClientAndServer : Connection, IClientAndServer
	{
		IServer server;
		IClient client;

		public IServer Server {
			get { return server; }
		}

		public IClient Client {
			get { return client; }
		}

		public ClientAndServer (ClientAndServerFactory factory, IServer server, IClient client, IClientAndServerParameters parameters)
			: base (factory, server.EndPoint, parameters)
		{
			this.server = server;
			this.client = client;
		}

		public override TlsConnectionInfo GetConnectionInfo ()
		{
			throw new InvalidOperationException ();
		}

		public override async Task Start ()
		{
			await server.Start ();
			await client.Start ();
		}

		public override async Task WaitForConnection ()
		{
			var serverTask = server.WaitForConnection ();
			var clientTask = client.WaitForConnection ();

			var t1 = clientTask.ContinueWith (t => {
				if (t.IsFaulted || t.IsCanceled)
					server.Dispose ();
			});
			var t2 = serverTask.ContinueWith (t => {
				if (t.IsFaulted || t.IsCanceled)
					client.Dispose ();
			});

			await Task.WhenAll (serverTask, clientTask, t1, t2);
		}

		protected override void Stop ()
		{
			client.Dispose ();
			server.Dispose ();
		}

		public override async Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply)
		{
			var clientShutdown = client.Shutdown (attemptCleanShutdown, waitForReply);
			var serverShutdown = server.Shutdown (attemptCleanShutdown, waitForReply);
			await Task.WhenAll (clientShutdown, serverShutdown);
			return clientShutdown.Result && serverShutdown.Result;
		}
	}
}

