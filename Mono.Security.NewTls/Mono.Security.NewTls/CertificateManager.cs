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

			#if FIXME
			var leaf = certificates [0];
			var chain = new MX.X509Chain ();
			chain.LoadCertificates (certificates);
			var ok = chain.Build (leaf);
			var errors = GetStatus (chain.Status);
			#endif

			var helper = config.CertificateValidator;
			if (helper == null)
				helper = CertificateValidationHelper.CreateDefaultValidator (config.UserSettings);

			var result = helper.ValidateChain (config.TargetHost, certificates);
			if (result.Trusted)
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
				if (!config.UserSettings.RequireClientCertificate)
					return false;
				throw new TlsException (AlertDescription.CertificateUnknown);
			}

			var leaf = certificates [0];
			var chain = new MX.X509Chain ();
			chain.LoadCertificates (certificates);
			var ok = chain.Build (leaf);
			var errors = GetStatus (chain.Status);

			var certParams = config.UserSettings.ClientCertificateParameters;
			if (certParams.CertificateAuthorities.Count > 0) {
				if (!certParams.CertificateAuthorities.Contains (leaf.IssuerName))
					throw new TlsException (AlertDescription.BadCertificate);
			}

			if (config.UserSettings.ClientCertValidationCallback != null)
				ok = config.UserSettings.ClientCertValidationCallback (certParams, leaf, chain, errors);

			if (!ok)
				throw new TlsException (AlertDescription.CertificateUnknown);
			return true;
		}
	}
}

