using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Mono.Security.NewTls
{
	using Cipher;
	using Extensions;
	using Instrumentation;
	using X509;

	internal class Session : DisposeContext
	{
		RandomNumberGenerator rng;
		CryptoParameters currentCrypto;
		CryptoParameters pendingCrypto;
		SecureBuffer clientVerifyData;
		SecureBuffer serverVerifyData;
		bool hasSignatureParameters;
		SignatureParameters signatureParameters;
		SignatureAndHashAlgorithm? serverSignatureAlgorithm;
		bool hasCertificateParameters;
		ClientCertificateParameters certificateParameters;

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

		internal bool HasSignatureParameters {
			get { return hasSignatureParameters; }
		}

		internal SignatureParameters SignatureParameters {
			get {
				if (!hasSignatureParameters)
					throw new InvalidOperationException ();
				return signatureParameters;
			}
			set {
				signatureParameters = value;
				hasSignatureParameters = true;
			}
		}

		internal SignatureAndHashAlgorithm ServerSignatureAlgorithm {
			get {
				if (!hasSignatureParameters || serverSignatureAlgorithm == null)
					throw new InvalidOperationException ();
				return serverSignatureAlgorithm.Value;
			}
			set {
				if (!hasSignatureParameters)
					throw new InvalidOperationException ();
				serverSignatureAlgorithm = value;
			}
		}

		internal bool HasCertificateParameters {
			get { return hasCertificateParameters; }
		}

		internal ClientCertificateParameters ClientCertificateParameters {
			get {
				if (!hasCertificateParameters)
					throw new InvalidOperationException ();
				return certificateParameters;
			}
			set {
				certificateParameters = value;
				hasCertificateParameters = true;
			}
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
			signatureParameters = null;
			hasSignatureParameters = false;
			serverSignatureAlgorithm = null;
		}
	}
}

