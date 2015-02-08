namespace Mono.Security.Protocol.NewTls
{
	public struct SignatureAndHashAlgorithm
	{
		public readonly HashAlgorithmType Hash;
		public readonly SignatureAlgorithmType Signature;

		internal SignatureAndHashAlgorithm (TlsBuffer buffer)
		{
			Hash = (HashAlgorithmType)buffer.ReadByte ();
			Signature = (SignatureAlgorithmType)buffer.ReadByte ();
		}

		internal void Encode (TlsStream stream)
		{
			stream.Write ((byte)Hash);
			stream.Write ((byte)Signature);
		}

		internal void Encode (TlsBuffer buffer)
		{
			buffer.Write ((byte)Hash);
			buffer.Write ((byte)Signature);
		}

		public SignatureAndHashAlgorithm (HashAlgorithmType hash, SignatureAlgorithmType signature)
		{
			Hash = hash;
			Signature = signature;
		}

		public override int GetHashCode ()
		{
			return Hash.GetHashCode ();
		}

		public override bool Equals (object obj)
		{
			var other = (SignatureAndHashAlgorithm)obj;
			return other.Hash == Hash && other.Signature == Signature;
		}

		public override string ToString ()
		{
			return string.Format ("[SignatureAndHashAlgorithm: {0} {1}]", Hash, Signature);
		}
	}
}

