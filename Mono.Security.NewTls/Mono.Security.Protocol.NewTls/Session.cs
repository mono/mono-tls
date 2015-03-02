using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Mono.Security.NewTls
{
	using Cipher;
	using Extensions;
	using X509;

	internal class Session : DisposeContext
	{
		RandomNumberGenerator rng;
		CryptoParameters currentCrypto;
		CryptoParameters pendingCrypto;
		SecureBuffer clientVerifyData;
		SecureBuffer serverVerifyData;

		public TlsConfiguration Configuration {
			get;
			private set;
		}

		internal CryptoParameters CurrentCrypto {
			get { return currentCrypto; }
			set { currentCrypto = Add (value); }
		}

		internal CryptoParameters PendingCrypto {
			get { return pendingCrypto; }
			set { pendingCrypto = Add (value); }
		}

		internal bool PendingRead {
			get; set;
		}

		internal bool PendingWrite {
			get; set;
		}

		internal CryptoParameters Read {
			get { return PendingRead ? PendingCrypto : CurrentCrypto; }
		}

		internal CryptoParameters Write {
			get { return PendingWrite ? PendingCrypto : CurrentCrypto; }
		}

		internal bool SecureRenegotiation {
			get; set;
		}

		internal SecureBuffer ClientVerifyData {
			get { return clientVerifyData; }
			set { clientVerifyData = Add (value); }
		}

		internal SecureBuffer ServerVerifyData {
			get { return serverVerifyData; }
			set { serverVerifyData = Add (value); }
		}

		internal RandomNumberGenerator RandomNumberGenerator {
			get { return rng; }
			set {
#if !BOOTSTRAP_BASIC
				rng = Add (value);
#else
				throw new NotSupportedException ();
#endif
			}
		}

		internal SecureBuffer GetSecureRandomBytes (int size)
		{
			var secureBytes = new SecureBuffer (size);
			RandomNumberGenerator.GetNonZeroBytes (secureBytes.Buffer);
			return secureBytes;
		}

		public Session (TlsConfiguration configuration)
		{
			Configuration = configuration;
		}

		protected override void Clear ()
		{
			base.Clear ();
			PendingRead = false;
			PendingWrite = false;
		}
	}
}

