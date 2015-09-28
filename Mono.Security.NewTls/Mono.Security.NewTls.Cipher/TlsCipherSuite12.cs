using System;
using System.Text;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class TlsCipherSuite12 : CipherSuite
	{
		public TlsCipherSuite12 (
			CipherSuiteCode code, CipherAlgorithmType cipherAlgorithmType,
			HashAlgorithmType hashAlgorithmType, ExchangeAlgorithmType exchangeAlgorithmType)
			: base (code, cipherAlgorithmType, hashAlgorithmType, exchangeAlgorithmType)
		{
		}

		public override HandshakeHashType HandshakeHashType {
			get {
				if (CipherAlgorithmType == CipherAlgorithmType.AesGcm256 && HashAlgorithmType == HashAlgorithmType.Sha384)
					return HandshakeHashType.SHA384;
				else if (HashAlgorithmType == HashAlgorithmType.Sha384)
					return HandshakeHashType.SHA384;
				else
					return HandshakeHashType.SHA256;
			}
		}

		public override short EffectiveKeyBits {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
				case CipherAlgorithmType.AesGcm128:
					return 128;
				case CipherAlgorithmType.Aes256:
				case CipherAlgorithmType.AesGcm256:
					return 256;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override bool HasHMac {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
				case CipherAlgorithmType.Aes256:
					return true;
				case CipherAlgorithmType.AesGcm128:
				case CipherAlgorithmType.AesGcm256:
					return false;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override int HashSize {
			get {
				if (!HasHMac)
					return 0;
				switch (HashAlgorithmType) {
				case HashAlgorithmType.Sha1:
					return 20;
				case HashAlgorithmType.Sha256:
					return 32;
				case HashAlgorithmType.Sha384:
					return 48;
				case HashAlgorithmType.None:
					return 0;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override byte KeyMaterialSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
				case CipherAlgorithmType.AesGcm128:
					return 16;
				case CipherAlgorithmType.Aes256:
				case CipherAlgorithmType.AesGcm256:
					return 32;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override byte ExpandedKeyMaterialSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
				case CipherAlgorithmType.AesGcm128:
					return 16;
				case CipherAlgorithmType.Aes256:
				case CipherAlgorithmType.AesGcm256:
					return 32;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override byte FixedIvSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.AesGcm128:
				case CipherAlgorithmType.AesGcm256:
					return 4;
				default:
					return 0;
				}
			}
		}

		public override byte BlockSize {
			get {
				switch (CipherAlgorithmType) {
				case CipherAlgorithmType.Aes128:
				case CipherAlgorithmType.Aes256:
				case CipherAlgorithmType.AesGcm128:
				case CipherAlgorithmType.AesGcm256:
					return 16;
				default:
					throw new NotSupportedException ();
				}
			}
		}

		public override CryptoParameters Initialize (bool isServer, TlsProtocolCode protocol)
		{
			switch (CipherAlgorithmType) {
			case CipherAlgorithmType.AesGcm128:
			case CipherAlgorithmType.AesGcm256:
				return new GaloisCounterCipher (isServer, protocol, this);
			case CipherAlgorithmType.Aes128:
			case CipherAlgorithmType.Aes256:
				return new CbcBlockCipher (isServer, protocol, this);
			default:
				throw new NotSupportedException ();
			}
		}

		protected override PseudoRandomFunction CreatePseudoRandomFunction ()
		{
			return new PseudoRandomFunctionTls12 (HandshakeHashType);
		}
	}
}

