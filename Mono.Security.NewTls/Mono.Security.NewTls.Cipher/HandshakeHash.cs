using System;
using System.Security.Cryptography;
using MSC = Mono.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Cipher
{
	using Handshake;

	class HandshakeHash : SecretParameters
	{
		IHashAlgorithm[] hashes;

		public HandshakeHash ()
		{
			hashes = new IHashAlgorithm [6];
			hashes [0] = new MSC.MD5SHA1 ();
			hashes [1] = new MSC.SHA1CryptoServiceProvider ();
			hashes [2] = new MSC.SHA224Managed ();
			hashes [3] = new MSC.SHA256Managed ();
			hashes [4] = new MSC.SHA384Managed ();
			hashes [5] = new MSC.SHA512Managed ();
		}

		public void Add (HandshakeMessage message, IBufferOffsetSize buffer)
		{
			if (message is TlsHelloRequest)
				throw new InvalidOperationException ();
			for (int i = 0; i < hashes.Length; i++)
				hashes [i].TransformBlock (buffer.Buffer, buffer.Offset, buffer.Size);
		}

		IHashAlgorithm GetAlgorithm (HandshakeHashType type)
		{
			switch (type) {
			case HandshakeHashType.MD5SHA1:
				return hashes [0];
			case HandshakeHashType.SHA256:
				return hashes [3];
			case HandshakeHashType.SHA384:
				return hashes [4];
			default:
				throw new InvalidOperationException ();
			}
		}

		IHashAlgorithm GetAlgorithm (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5Sha1:
				return hashes [0];
			case HashAlgorithmType.Sha1:
				return hashes [1];
			case HashAlgorithmType.Sha224:
				return hashes [2];
			case HashAlgorithmType.Sha256:
				return hashes [3];
			case HashAlgorithmType.Sha384:
				return hashes [4];
			case HashAlgorithmType.Sha512:
				return hashes [5];
			default:
				throw new NotSupportedException ();
			}
		}

		public SecureBuffer GetHash (HandshakeHashType type)
		{
			return new SecureBuffer (GetAlgorithm (type).GetRunningHash ());
		}

		public void CreateSignature (Signature signature, AsymmetricAlgorithm key)
		{
			var algorithm = GetAlgorithm (signature.HashAlgorithm);
			signature.Create (algorithm.GetRunningHash (), key);
		}

		public bool VerifySignature (Signature signature, AsymmetricAlgorithm key)
		{
			var algorithm = GetAlgorithm (signature.HashAlgorithm);
			return signature.Verify (algorithm.GetRunningHash (), key);
		}

		protected override void Clear ()
		{
			for (int i = 0; i < hashes.Length; i++) {
				hashes [0].Dispose ();
			}
		}
	}
}

