using System;

namespace Mono.Security.Protocol.NewTls
{
	public abstract class SecretParameters : IDisposable
	{
		protected abstract void Clear ();

		bool disposed;

		protected void CheckDisposed ()
		{
			if (disposed)
				throw new ObjectDisposedException (GetType ().Name);
		}

		protected static void Clear (byte[] array)
		{
			Array.Clear (array, 0, array.Length);
		}

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

		void Dispose (bool disposing)
		{
			if (!disposed) {
				disposed = true;
				Clear ();
			}
		}

		~SecretParameters ()
		{
			Dispose (false);
		}
	}
}

