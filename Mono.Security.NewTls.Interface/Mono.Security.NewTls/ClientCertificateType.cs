namespace Mono.Security.NewTls
{
	public enum ClientCertificateType
	{
		RsaSign			= 1,
		DsaSign			= 2,
		RsaFixedDh		= 3,
		DssFixedDh		= 4,

		RsaEphemeralDh_Reserved	= 5,
		DssEphemeralDh_Reserved	= 6,
		FortezzaDms_Reserved	= 20,

		Unknown			= 255
	}
}
