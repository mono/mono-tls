namespace Mono.Security.NewTls
{
	public enum HashAlgorithmType
	{
		// These values refer to the @HashAlgorithm enumeration in the TLS 1.2 spec.
		None	= 0,
		Md5	= 1,
		Sha1	= 2,
		Sha224	= 3,
		Sha256	= 4,
		Sha384	= 5,
		Sha512	= 6,
		Unknown	= 255,

		// Mono-specific addition, allowing us to reuse it IHashAlgorithm API for TLS 1.0 / 1.1.
		Md5Sha1	= 254
	}
}
