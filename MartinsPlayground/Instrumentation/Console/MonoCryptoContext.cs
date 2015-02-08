using System;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;
using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Cipher;
using Mono.Security.Protocol.NewTls.Handshake;

namespace Mono.Security.Instrumentation.Console
{
	using Framework;

	class MonoCryptoContext : DisposeContext, ICryptoTestContext
	{
		public TlsProtocolCode Protocol {
			get;
			private set;
		}

		public bool IsServer {
			get;
			private set;
		}

		public CipherSuite Cipher {
			get;
			private set;
		}

		public CryptoParameters Crypto {
			get;
			private set;
		}

		public bool EnableDebugging {
			get; set;
		}

		public byte ExtraPaddingBlocks {
			get; set;
		}

		public MonoCryptoContext (TlsProtocolCode protocol, bool isServer)
		{
			Protocol = protocol;
			IsServer = isServer;
		}

		class MyCbcBlockCipher : CbcBlockCipher
		{
			MonoCryptoContext context;
			byte[] iv;

			public MyCbcBlockCipher (MonoCryptoContext context, byte[] iv)
				: base (context.IsServer, context.Protocol, context.Cipher)
			{
				this.context = context;
				this.iv = iv;
			}

			protected override SymmetricAlgorithm CreateEncryptionAlgorithm (bool forEncryption)
			{
				return new MyAlgorithm (base.CreateEncryptionAlgorithm (forEncryption), iv);
			}

			protected override byte GetPaddingSize (int size)
			{
				var padLen = (byte)(BlockSize - size % BlockSize);
				if (padLen == BlockSize)
					padLen = 0;

				padLen += (byte)(context.ExtraPaddingBlocks * BlockSize);

				return padLen;
			}
		}

		class MyAlgorithm : SymmetricAlgorithmProxy
		{
			byte[] iv;

			public MyAlgorithm (SymmetricAlgorithm algorithm, byte[] iv)
				: base (algorithm)
			{
				this.iv = iv;
			}

			public override void GenerateIV ()
			{
				base.IV = iv;
			}
		}

		class MyGaloisCounterCipher : GaloisCounterCipher
		{
			byte[] iv;

			public MyGaloisCounterCipher (bool isServer, TlsProtocolCode protocol, CipherSuite cipher, byte[] iv)
				: base (isServer, protocol, cipher)
			{
				this.iv = iv;
			}

			protected override void CreateExplicitNonce (SecureBuffer explicitNonce)
			{
				Buffer.BlockCopy (iv, 0, explicitNonce.Buffer, 0, iv.Length);
			}
		}

		public int BlockSize {
			get { return Cipher.BlockSize; }
		}

		public int GetEncryptedSize (int size)
		{
			return Crypto.GetEncryptedSize (size);
		}

		public int MinExtraEncryptedBytes {
			get { return Crypto.MinExtraEncryptedBytes; }
		}

		public int MaxExtraEncryptedBytes {
			get { return Crypto.MaxExtraEncryptedBytes; }
		}

		public void InitializeCBC (CipherSuiteCode code, byte[] key, byte[] mac, byte[] iv)
		{
			Cipher = CipherSuiteFactory.CreateCipherSuite (Protocol, code);
			#if DEBUG_FULL
			Cipher.EnableDebugging = EnableDebugging;
			#endif
			Crypto = Add (new MyCbcBlockCipher (this, iv));

			Crypto.ServerWriteKey = SecureBuffer.CreateCopy (key);
			Crypto.ClientWriteKey = SecureBuffer.CreateCopy (key);
			Crypto.ServerWriteMac = SecureBuffer.CreateCopy (mac);
			Crypto.ClientWriteMac = SecureBuffer.CreateCopy (mac);

			Crypto.InitializeCipher ();
		}

		public void InitializeGCM (CipherSuiteCode code, byte[] key, byte[] implNonce, byte[] explNonce)
		{
			Cipher = CipherSuiteFactory.CreateCipherSuite (Protocol, code);
			#if DEBUG_FULL
			Cipher.EnableDebugging = EnableDebugging;
			#endif
			Crypto = Add (new MyGaloisCounterCipher (IsServer, Protocol, Cipher, explNonce));

			Crypto.ServerWriteKey = SecureBuffer.CreateCopy (key);
			Crypto.ClientWriteKey = SecureBuffer.CreateCopy (key);
			Crypto.ServerWriteIV = SecureBuffer.CreateCopy (implNonce);
			Crypto.ClientWriteIV = SecureBuffer.CreateCopy (implNonce);

			Crypto.InitializeCipher ();
		}

		public void EncryptRecord (ContentType contentType, IBufferOffsetSize input, TlsStream output)
		{
			Crypto.WriteSequenceNumber = 0;
			TlsContext.EncodeRecord (Protocol, ContentType.ApplicationData, Crypto, input, output);
		}

		public IBufferOffsetSize Encrypt (IBufferOffsetSize input)
		{
			Crypto.WriteSequenceNumber = 0;
			return Crypto.Encrypt (ContentType.ApplicationData, input);
		}

		public int Encrypt (IBufferOffsetSize input, IBufferOffsetSize output)
		{
			Crypto.WriteSequenceNumber = 0;
			return Crypto.Encrypt (ContentType.ApplicationData, input, output);
		}

		public IBufferOffsetSize Decrypt (IBufferOffsetSize input)
		{
			Crypto.ReadSequenceNumber = 0;
			return Crypto.Decrypt (ContentType.ApplicationData, input);
		}

		public int Decrypt (IBufferOffsetSize input, IBufferOffsetSize output)
		{
			Crypto.ReadSequenceNumber = 0;
			return Crypto.Decrypt (ContentType.ApplicationData, input, output);
		}
	}
}

