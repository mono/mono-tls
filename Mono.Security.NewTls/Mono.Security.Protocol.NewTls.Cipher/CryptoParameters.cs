using System;
using System.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.Protocol.NewTls.Cipher
{
	using X509;

	abstract class CryptoParameters : DisposeContext
	{
		bool isServer;
		CipherSuite cipher;
		SecureBuffer masterSecret;
		SecureBuffer clientWriteMac;
		SecureBuffer serverWriteMac;
		SecureBuffer clientWriteKey;
		SecureBuffer serverWriteKey;
		SecureBuffer clientWriteIV;
		SecureBuffer serverWriteIV;
		SecureBuffer certificateSignature;
		ulong writeSequenceNumber;
		ulong readSequenceNumber;
		TlsProtocolCode protocol;
		X509CertificateCollection clientCertificates;
		X509CertificateCollection serverCertificates;

		internal CryptoParameters (bool isServer, TlsProtocolCode protocol, CipherSuite cipher)
		{
			this.isServer = isServer;
			this.protocol = protocol;
			this.cipher = cipher;
		}

		public bool IsAtLeastTls12 {
			get { return TlsConfiguration.IsTls12OrNewer (protocol); }
		}

		public bool IsServer {
			get { return isServer; }
		}

		public bool IsClient {
			get { return !isServer; }
		}

		public TlsProtocolCode Protocol {
			get { return protocol; }
		}

		public CipherSuite Cipher {
			get { return cipher; }
		}

		public SecureBuffer MasterSecret {
			get { return masterSecret; }
			set { masterSecret = Add (value); }
		}

		public SecureBuffer ClientWriteMac {
			get { return clientWriteMac; }
			set { clientWriteMac = Add (value); }
		}

		public SecureBuffer ServerWriteMac {
			get { return serverWriteMac; }
			set { serverWriteMac = Add (value); }
		}

		public SecureBuffer ClientWriteKey {
			get { return clientWriteKey; }
			set { clientWriteKey = Add (value); }
		}

		public SecureBuffer ServerWriteKey {
			get { return serverWriteKey; }
			set { serverWriteKey = Add (value); }
		}

		internal X509CertificateCollection ClientCertificates {
			get { return clientCertificates; }
			set { clientCertificates = value; }
		}

		internal X509CertificateCollection ServerCertificates {
			get { return serverCertificates; }
			set { serverCertificates = value; }
		}

		internal bool ServerCertificateVerified {
			get; set;
		}

		public SecureBuffer CertificateSignature {
			get { return certificateSignature; }
			set { certificateSignature = Add (value); }
		}

		public SignatureAndHashAlgorithm CertificateSignatureType {
			get; set;
		}

		void RequireFixedIV ()
		{
			if (!Cipher.HasFixedIV)
				throw new InvalidOperationException ();
		}

		public SecureBuffer ClientWriteIV {
			get {
				RequireFixedIV ();
				return clientWriteIV;
			}
			set {
				RequireFixedIV ();
				clientWriteIV = value;
			}
		}

		public SecureBuffer ServerWriteIV {
			get {
				RequireFixedIV ();
				return serverWriteIV;
			}
			set {
				RequireFixedIV ();
				serverWriteIV = value;
			}
		}

		public ulong WriteSequenceNumber {
			get { return writeSequenceNumber; }
			set { writeSequenceNumber = value; }
		}

		public ulong ReadSequenceNumber {
			get { return readSequenceNumber; }
			set { readSequenceNumber = value; }
		}

		protected override void Clear ()
		{
			base.Clear ();
			cipher = null;
			writeSequenceNumber = 0;
			readSequenceNumber = 0;
		}

		public abstract void InitializeCipher ();

		public abstract int MinExtraEncryptedBytes {
			get;
		}

		public abstract int MaxExtraEncryptedBytes {
			get;
		}

		public abstract int GetEncryptedSize (int size);

		public IBufferOffsetSize Encrypt (ContentType contentType, IBufferOffsetSize data)
		{
			var output = new BufferOffsetSize (GetEncryptedSize (data.Size));
			var ret = Encrypt (contentType, data, output);
			output.TruncateTo (ret);
			return output;
		}

		public int Encrypt (ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			if (output == null || output == input || output.Buffer == input.Buffer)
				throw new TlsException (AlertDescription.InternalError, "In-place encryption is not supported.");
			if (output.Size < GetEncryptedSize (input.Size))
				throw new TlsException (AlertDescription.InternalError, "Output buffer overflow.");

			using (var d = new DisposeContext ()) {
				var ret = Encrypt (d, contentType, input, output);

				// Update sequence number
				WriteSequenceNumber++;

				if (ret < 0)
					throw new TlsException (AlertDescription.BadRecordMAC);
				return ret;
			}
		}

		public IBufferOffsetSize Decrypt (ContentType contentType, IBufferOffsetSize input)
		{
			var output = new BufferOffsetSize (input.Size);
			var ret = Decrypt (contentType, input, output);
			output.TruncateTo (ret);
			return output;
		}

		public int Decrypt (ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			if (output == null || output == input || output.Buffer == input.Buffer)
				throw new TlsException (AlertDescription.InternalError, "In-place decryption is not supported.");
			if (output.Size < input.Size)
				throw new TlsException (AlertDescription.InternalError, "Output buffer overflow.");

			using (var d = new DisposeContext ()) {
				var ret = Decrypt (d, contentType, input, output);

				// Update sequence number
				ReadSequenceNumber++;

				if (ret < 0)
					throw new TlsException (AlertDescription.BadRecordMAC);
				return ret;
			}
		}

		/*
		 * Returns -1 on error because for some of the Cipher Suites (such as the CBC Block Cipher) it is strictly forbidden
		 * to throw any Exceptions in here.
		 * 
		 */

		protected abstract int Encrypt (DisposeContext d, ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output);

		protected abstract int Decrypt (DisposeContext d, ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output);
	}
}

