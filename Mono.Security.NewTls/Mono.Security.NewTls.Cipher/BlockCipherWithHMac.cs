using System;
using System.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Cipher
{
	abstract class BlockCipherWithHMac : BlockCipher
	{
		HMac clientHMac;
		HMac serverHMac;

		internal HMac ClientHMac {
			get { return clientHMac; }
			set { clientHMac = Add (value); }
		}

		internal HMac ServerHMac {
			get { return serverHMac; }
			set { serverHMac = Add (value); }
		}

		public BlockCipherWithHMac (bool isServer, TlsProtocolCode protocol, CipherSuite cipher)
			: base (isServer, protocol, cipher)
		{
			MacSize = HMac.GetMacSize (Cipher.HashAlgorithmType);
		}

		public int MacSize {
			get;
			private set;
		}

		public override void InitializeCipher ()
		{
			// Create the HMAC algorithm
			if (IsClient) {
				ClientHMac = HMac.Create (Cipher.HashAlgorithmType, ClientWriteMac);
				ServerHMac = HMac.Create (Cipher.HashAlgorithmType, ServerWriteMac);
			} else {
				ServerHMac = HMac.Create (Cipher.HashAlgorithmType, ServerWriteMac);
				ClientHMac = HMac.Create (Cipher.HashAlgorithmType, ClientWriteMac);
			}
		}

		protected abstract int HeaderSize {
			get;
		}

		protected virtual byte GetPaddingSize (int size)
		{
			var padLen = (byte)(BlockSize - size % BlockSize);
			if (padLen == BlockSize)
				padLen = 0;
			return padLen;
		}

		int GetEncryptedSize (int size, out int plen, out byte padLen)
		{
			plen = HeaderSize + size + MacSize + 1;

			padLen = GetPaddingSize (plen);

			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteLine ("GET ENCRYPTED SIZE: {0} {1} {2} -> {3} + {4} = {5}", size, MacSize, BlockSize, plen, padLen, plen + padLen);
			#endif

			return plen + padLen;
		}

		public override int MinExtraEncryptedBytes {
			get { return HeaderSize + MacSize + 1; }
		}

		public override int MaxExtraEncryptedBytes {
			get { return MinExtraEncryptedBytes + BlockSize - 1; }
		}

		public override int GetEncryptedSize (int size)
		{
			int plen;
			byte padLen;

			return GetEncryptedSize (size, out plen, out padLen);
		}

		static byte[] ComputeRecordMAC (TlsProtocolCode protocol, HMac hmac, ulong seqnum, ContentType contentType, IBufferOffsetSize fragment)
		{
			var header = new TlsBuffer (13);
			header.Write (seqnum);
			header.Write ((byte)contentType);
			header.Write ((short)protocol);
			header.Write ((short)fragment.Size);

			hmac.TransformBlock (header.Buffer, 0, header.Size);
			hmac.TransformBlock (fragment.Buffer, fragment.Offset, fragment.Size);
			return hmac.TransformFinalBlock ();
		}

		byte[] ComputeClientRecordMAC (ContentType contentType, IBufferOffsetSize fragment)
		{
			var seqnum = IsClient ? WriteSequenceNumber : ReadSequenceNumber;
			return ComputeRecordMAC (Protocol, ClientHMac, seqnum, contentType, fragment);
		}

		byte[] ComputeServerRecordMAC (ContentType contentType, IBufferOffsetSize fragment)
		{
			var seqnum = IsClient ? ReadSequenceNumber : WriteSequenceNumber;
			return ComputeRecordMAC (Protocol, ServerHMac, seqnum, contentType, fragment);
		}

		protected byte[] ComputeRecordMAC (ContentType contentType, IBufferOffsetSize fragment)
		{
			if (IsServer)
				return ComputeClientRecordMAC (contentType, fragment);
			else
				return ComputeServerRecordMAC (contentType, fragment);
		}

		protected abstract void EncryptRecord (DisposeContext d, IBufferOffsetSize buffer);

		protected abstract int DecryptRecord (DisposeContext d, IBufferOffsetSize input, IBufferOffsetSize output);

		protected override int Encrypt (DisposeContext d, ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			// Calculate message MAC
			byte[] mac = null;
			if (IsServer)
				mac = ComputeServerRecordMAC (contentType, input);
			else
				mac = ComputeClientRecordMAC (contentType, input);

			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteLine ("RECORD MAC", mac);
			#endif

			int plen;
			byte padLen;
			int totalLength = GetEncryptedSize (input.Size, out plen, out padLen);

			var totalOutput = new BufferOffsetSize (output.Buffer, output.Offset, totalLength);
			var outputWriter = new TlsBuffer (totalOutput);

			outputWriter.Position += HeaderSize;

			outputWriter.Write (input.Buffer, input.Offset, input.Size);
			outputWriter.Write (mac);

			for (int i = 0; i <= padLen; i++)
				outputWriter.Write (padLen);

			// Encrypt the message
			EncryptRecord (d, totalOutput);
			return totalLength;
		}

		protected override int Decrypt (DisposeContext d, ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			if ((input.Size % BlockSize) != 0)
				return -1;
			if (input.Size < MinExtraEncryptedBytes)
				return -1;

			var plen = DecryptRecord (d, input, output);
			if (plen <= 0)
				return -1;

			var padlen = output.Buffer [output.Offset + plen - 1];
			#if DEBUG_FULL
			if (Cipher.EnableDebugging) {
				DebugHelper.WriteLine ("DECRYPT: {0} {1} {2}", input.Size, plen, padlen);
				DebugHelper.WriteBuffer (output.Buffer, output.Offset, plen);
			}
			#endif

			/*
			 * VERY IMPORTANT:
			 * 
			 * The Compiler and JIT *** MUST NOT *** optimize the following block of code.
			 * 
			 * It is essential that the dummy checks and dummy calls be kept in place.
			 * Also do not put any debugging code into that region as it would mess up with
			 * the timing.
			 * 
			 */

			#region The following block of code *** MUST NOT *** be optimized in any way

			if (MacSize + padlen + 1 > plen) {
				// Invalid padding: plaintext is not long enough.

				// First run a loop as if there were 256 bytes of padding, with a dummy check.
				int ok = -1;
				for (int i = 0; i < 256; i++) {
					if (output.Buffer [i % output.Size] != padlen)
						ok--;
				}

				// Now assume there's no padding, compute the MAC over the entire buffer.
				var first = new BufferOffsetSize (output.Buffer, output.Offset, plen - MacSize);
				var invalidMac = ComputeRecordMAC (contentType, first);

				// Constant-time compare - this will always fail, TlsBuffer.ConstantTimeCompare() will return a negative value on error.
				ok += TlsBuffer.ConstantTimeCompare (invalidMac, 0, invalidMac.Length, output.Buffer, output.Offset + plen - MacSize, MacSize);
				return ok;
			} else {
				int ok = 0;
				var resultLength = plen - padlen - MacSize - 1;
				for (int i = 0; i < padlen; i++) {
					if (output.Buffer [output.Offset + resultLength + MacSize + i] != padlen)
						ok--;
				}

				var dummyOk = ok;
				var dummyLen = 256 - padlen - 1;
				for (int i = 0; i < dummyLen; i++) {
					if (output.Buffer [i % output.Size] != padlen)
						dummyOk--;
				}

				if (ok < 0) {
					// Now assume there's no padding, compute the MAC over the entire buffer.
					var first = new BufferOffsetSize (output.Buffer, output.Offset, plen - MacSize);
					var invalidMac = ComputeRecordMAC (contentType, first);

					// Constant-time compare - this will always fail, TlsBuffer.ConstantTimeCompare() will return a negative value on error.
					ok += TlsBuffer.ConstantTimeCompare (invalidMac, 0, invalidMac.Length, output.Buffer, output.Offset + plen - MacSize, MacSize);
					return ok;
				} else {
					var first = new BufferOffsetSize (output.Buffer, output.Offset, resultLength);
					var checkMac = ComputeRecordMAC (contentType, first);

					var L1 = 13 + plen - MacSize;
					var L2 = 13 + plen - padlen - 1 - MacSize;

					var additional = ((L1 - 55) / 64) - ((L2 - 55) / 64);
					if (additional > 0) {
						var algorithm = HMac.CreateHash (Cipher.HashAlgorithmType);
						for (int i = 0; i < additional; i++)
							algorithm.TransformBlock (input.Buffer, input.Offset, BlockSize, null, 0);
					}

					ok += TlsBuffer.ConstantTimeCompare (checkMac, 0, checkMac.Length, output.Buffer, output.Offset + resultLength, MacSize);
					if (ok == 0)
						ok = resultLength;
					return ok;
				}
			}

			#endregion
		}
	}
}

