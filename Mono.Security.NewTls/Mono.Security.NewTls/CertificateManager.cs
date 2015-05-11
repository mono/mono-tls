using System;
using System.Net.Security;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	using MX = Mono.Security.X509;
	using SSCX = System.Security.Cryptography.X509Certificates;

	public static class CertificateManager
	{
		internal static void CheckRemoteCertificate (TlsConfiguration config, MX.X509CertificateCollection certificates)
		{
			if (certificates == null || certificates.Count < 1)
				throw new TlsException (AlertDescription.CertificateUnknown);

			var helper = config.CertificateValidator;
			if (helper == null)
				helper = CertificateValidationHelper.CreateDefaultValidator (config.UserSettings);

			var result = helper.ValidateChain (config.TargetHost, certificates);
			if (result != null && result.Trusted && !result.UserDenied)
				return;

			// FIXME: check other values to report correct error type.
			throw new TlsException (AlertDescription.CertificateUnknown);
		}

		static SslPolicyErrors GetStatus (MX.X509ChainStatusFlags flags)
		{
			switch (flags) {
			case MX.X509ChainStatusFlags.NoError:
				return SslPolicyErrors.None;
			default:
				return SslPolicyErrors.RemoteCertificateChainErrors;
			}
		}

		internal static bool CheckClientCertificate (TlsConfiguration config, MX.X509CertificateCollection certificates)
		{
			if (certificates == null || certificates.Count < 1) {
				if (!config.UserSettings.AskForClientCertificate)
					return false;
				if (config.UserSettings.RequireClientCertificate)
					throw new TlsException (AlertDescription.CertificateUnknown);
			}

			var certParams = config.UserSettings.ClientCertificateParameters;
			if (certParams.CertificateAuthorities.Count > 0) {
				if (!certParams.CertificateAuthorities.Contains (certificates [0].IssuerName))
					throw new TlsException (AlertDescription.BadCertificate);
			}

			var helper = config.CertificateValidator;
			if (helper == null)
				helper = CertificateValidationHelper.CreateDefaultValidator (config.UserSettings);

			var result = helper.ValidateClientCertificate (certificates);
			if (result != null && result.Trusted && !result.UserDenied)
				return true;

			throw new TlsException (AlertDescription.CertificateUnknown);
		}
	}
}

