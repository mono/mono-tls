using System;
using System.Net.Security;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	using MX = Mono.Security.X509;
	using SSCX = System.Security.Cryptography.X509Certificates;

	internal static class CertificateManager
	{
		internal static void CheckRemoteCertificate (TlsConfiguration config, MX.X509CertificateCollection certificates)
		{
			if (certificates == null || certificates.Count < 1)
				throw new TlsException (AlertDescription.CertificateUnknown);

			var helper = config.CertificateValidator;
			if (helper == null)
				helper = CertificateValidationHelper.CreateDefaultValidator (config.TlsSettings);

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

		internal static bool CheckClientCertificate (TlsContext context, MX.X509CertificateCollection certificates)
		{
			if (certificates == null || certificates.Count < 1) {
				if (!context.SettingsProvider.AskForClientCertificate)
					return false;
				if (context.SettingsProvider.RequireClientCertificate)
					throw new TlsException (AlertDescription.CertificateUnknown);
			}

			if (context.SettingsProvider.HasClientCertificateParameters) {
				var certParams = context.SettingsProvider.ClientCertificateParameters;
				if (certParams.CertificateAuthorities.Count > 0) {
					if (!certParams.CertificateAuthorities.Contains (certificates [0].IssuerName))
						throw new TlsException (AlertDescription.BadCertificate);
				}
			}

			var helper = context.Configuration.CertificateValidator;
			if (helper == null)
				helper = CertificateValidationHelper.CreateDefaultValidator (context.Configuration.TlsSettings);

			var result = helper.ValidateClientCertificate (certificates);
			if (result != null && result.Trusted && !result.UserDenied)
				return true;

			throw new TlsException (AlertDescription.CertificateUnknown);
		}
	}
}

