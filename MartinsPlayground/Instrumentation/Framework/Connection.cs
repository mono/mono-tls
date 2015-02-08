using System;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Protocol.NewTls;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class Connection : IConnection, IDisposable
	{
		public ConnectionFactory Factory {
			get;
			private set;
		}

		public IPEndPoint EndPoint {
			get;
			private set;
		}

		public IConnectionParameters Parameters {
			get;
			private set;
		}

		protected Connection (ConnectionFactory factory, IPEndPoint endpoint, IConnectionParameters parameters)
		{
			Factory = factory;
			EndPoint = endpoint;
			Parameters = parameters;
		}

		public abstract Task Start ();

		public abstract Task WaitForConnection ();

		public abstract Task<bool> Shutdown (bool attemptCleanShutdown, bool waitForReply);

		protected abstract void Stop ();

		public abstract TlsConnectionInfo GetConnectionInfo ();

		protected Task FinishedTask {
			get { return Task.FromResult<object> (null); }
		}

		protected bool RemoteValidationCallback (bool ok, X509Certificate certificate)
		{
			Debug ("REMOTE VALIDATION CALLBACK: {0} {1}", ok, certificate.Subject);

			if (ok)
				return true;
			if (!Parameters.VerifyPeerCertificate)
				return true;
			if (Parameters.TrustedCA == null)
				return false;

			var caCert = new X509Certificate (Parameters.TrustedCA.Data);
			Debug ("Got Trusted CA Certificate: {0}", caCert.Subject);
			Debug ("Remote Certificate: {0}", certificate.Subject);

			Debug ("Remote Certificate Issuer: {0}", certificate.Issuer);

			return caCert.Subject.Equals (certificate.Issuer);
		}

		protected X509Certificate LocalCertificateSelectionCallback (string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
		{
			Debug ("LOCAL SELECTION CALLBACK: {0}", targetHost);
			return null;
		}

		protected void Debug (string message, params object[] args)
		{
			if (Parameters.EnableDebugging)
				Console.WriteLine ("[{0}]: {1}", GetType ().Name, string.Format (message, args));
		}

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

		bool disposed;

		protected virtual void Dispose (bool disposing)
		{
			lock (this) {
				if (disposed)
					return;
				disposed = true;
			}
			Stop ();
		}

		~Connection ()
		{
			Dispose (false);
		}
	}
}

