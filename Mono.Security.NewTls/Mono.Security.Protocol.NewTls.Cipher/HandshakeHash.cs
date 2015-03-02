using System;
using System.Security.Cryptography;
using Mono.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Cipher
{
	using Handshake;

	class HandshakeHash : SecretParameters
	{
		IRunningHash[] hashes;

		public HandshakeHash ()
		{
			hashes = new IRunningHash [5];
			hashes [0] = new MD5SHA1 ();
			hashes [1] = new SHA1CryptoServiceProvider ();
			hashes [2] = new SHA256Managed ();
			hashes [3] = new SHA384Managed ();
			hashes [4] = new SHA512Managed ();
		}

		public void Add (HandshakeMessage message, IBufferOffsetSize buffer)
		{
			if (message is TlsHelloRequest)
				throw new InvalidOperationException ();
			for (int i = 0; i < hashes.Length; i++)
				hashes [i].TransformBlock (buffer.Buffer, buffer.Offset, buffer.Size);
		}

		IRunningHash GetAlgorithm (HandshakeHashType type)
		{
			switch (type) {
			case HandshakeHashType.MD5SHA1:
				return hashes [0];
			case HandshakeHashType.SHA256:
				return hashes [2];
			case HandshakeHashType.SHA384:
				return hashes [3];
			default:
				throw new InvalidOperationException ();
			}
		}

		IRunningHash GetAlgorithm (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Sha1:
				return hashes [1];
			case HashAlgorithmType.Sha256:
				return hashes [2];
			case HashAlgorithmType.Sha384:
				return hashes [3];
			case HashAlgorithmType.Sha512:
				return hashes [4];
			default:
				throw new NotSupportedException ();
			}
		}

		public SecureBuffer GetHash (HandshakeHashType type)
		{
			return new SecureBuffer (GetAlgorithm (type).GetRunningHash ());
		}

		public SecureBuffer CreateSignature (SignatureAndHashAlgorithm type, AsymmetricAlgorithm key)
		{
			var algorithm = GetAlgorithm (type.Hash);
			using (var hash = new SecureBuffer (algorithm.GetRunningHash ()))
				return SignatureHelper.CreateSignature (type, (HashAlgorithm)algorithm, hash, key);
		}

		public bool VerifySignature (SignatureAndHashAlgorithm type, AsymmetricAlgorithm key, SecureBuffer signature)
		{
			var algorithm = GetAlgorithm (type.Hash);
			using (var hash = new SecureBuffer (algorithm.GetRunningHash ()))
				return SignatureHelper.VerifySignature (type, (HashAlgorithm)algorithm, hash, key, signature);
		}

		protected override void Clear ()
		{
			for (int i = 0; i < hashes.Length; i++) {
				hashes [0].Clear ();
			}
		}
	}
}

