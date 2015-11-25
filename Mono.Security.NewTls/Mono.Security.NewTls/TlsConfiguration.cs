using System;
using System.Net.Security;
using System.Security.Cryptography;
using MSI = Mono.Security.Interface;
using MX = Mono.Security.X509;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.NewTls
{
	public delegate bool RemoteCertValidationCallback (string host, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors);
	public delegate bool ClientCertValidationCallback (ClientCertificateParameters certParams, MX.X509Certificate certificate, MX.X509Chain chain, SslPolicyErrors sslPolicyErrors);
	public delegate SSCX.X509Certificate LocalCertSelectionCallback (string targetHost, SSCX.X509CertificateCollection localCertificates, SSCX.X509Certificate remoteCertificate, string[] acceptableIssuers);

	public class TlsConfiguration : SecretParameters
	{
		readonly MSI.TlsProtocols supportedProtocols;
		readonly MSI.TlsProtocolCode requestedProtocol;

		public MSI.TlsProtocols SupportedProtocols {
			get { return supportedProtocols; }
		}

		internal MSI.TlsProtocolCode RequestedProtocol {
			get { return requestedProtocol; }
		}

		public MSI.MonoTlsSettings TlsSettings {
			get;
			private set;
		}

		public UserSettings UserSettings {
			get;
			private set;
		}

		internal RenegotiationFlags RenegotiationFlags {
			get;
			private set;
		}

		public bool? AskForClientCertificate {
			get; set;
		}

		internal void ForceDisableRenegotiation ()
		{
			var abortOnHello = RenegotiationFlags & RenegotiationFlags.AbortOnHelloRequest;
			RenegotiationFlags = RenegotiationFlags.DisallowRenegotiation | abortOnHello;
		}

		internal bool EnableSecureRenegotiation {
			get {
				return (RenegotiationFlags & (RenegotiationFlags.DisallowRenegotiation | RenegotiationFlags.SecureRenegotiation)) == RenegotiationFlags.SecureRenegotiation;
			}
		}

		internal const RenegotiationFlags DefaultRenegotiationFlags = RenegotiationFlags.SecureRenegotiation | RenegotiationFlags.SendClientHelloExtension;

		public TlsConfiguration (MSI.TlsProtocols protocols, MSI.MonoTlsSettings settings, string targetHost)
		{
			supportedProtocols = protocols;
			requestedProtocol = CheckProtocol (settings, ref supportedProtocols, false);
			TlsSettings = settings;
			TargetHost = targetHost;

			if (settings != null)
				UserSettings = (UserSettings)settings.UserSettings;
			if (UserSettings == null)
				UserSettings = new UserSettings ();

			RenegotiationFlags = DefaultRenegotiationFlags;
		}

		public TlsConfiguration (MSI.TlsProtocols protocols, MSI.MonoTlsSettings settings, MX.X509Certificate certificate, AsymmetricAlgorithm privateKey)
		{
			supportedProtocols = protocols;
			requestedProtocol = CheckProtocol (settings, ref supportedProtocols, true);
			TlsSettings = settings;
			Certificate = certificate;
			PrivateKey = privateKey;

			if (settings != null)
				UserSettings = (UserSettings)settings.UserSettings;
			if (UserSettings == null)
				UserSettings = new UserSettings ();

			RenegotiationFlags = DefaultRenegotiationFlags;
		}

		#region Protocol Versions

		static MSI.TlsProtocolCode CheckProtocol (MSI.MonoTlsSettings settings, ref MSI.TlsProtocols protocols, bool isServer)
		{
			if (settings != null && settings.EnabledProtocols != null)
				protocols = (MSI.TlsProtocols)settings.EnabledProtocols.Value;

			if (isServer)
				protocols &= MSI.TlsProtocols.ServerMask;
			else
				protocols &= MSI.TlsProtocols.ClientMask;

			if (protocols == 0)
				throw new MSI.TlsException (MSI.AlertDescription.ProtocolVersion);

			if ((protocols & MSI.TlsProtocols.Tls12) != 0)
				return MSI.TlsProtocolCode.Tls12;
			if ((protocols & MSI.TlsProtocols.Tls11) != 0)
				return MSI.TlsProtocolCode.Tls11;
			if ((protocols & MSI.TlsProtocols.Tls10) != 0)
				return MSI.TlsProtocolCode.Tls10;

			throw new MSI.TlsException (MSI.AlertDescription.ProtocolVersion);
		}

		public bool IsSupportedClientProtocol (MSI.TlsProtocolCode protocol)
		{
			switch (protocol) {
			case MSI.TlsProtocolCode.Tls10:
				return (supportedProtocols & MSI.TlsProtocols.Tls10Server) != 0;
			case MSI.TlsProtocolCode.Tls11:
				return (supportedProtocols & MSI.TlsProtocols.Tls11Server) != 0;
			case MSI.TlsProtocolCode.Tls12:
				return (supportedProtocols & MSI.TlsProtocols.Tls12Server) != 0;
			default:
				return false;
			}
		}

		public bool IsSupportedServerProtocol (MSI.TlsProtocolCode protocol)
		{
			switch (protocol) {
			case MSI.TlsProtocolCode.Tls10:
				return (supportedProtocols & MSI.TlsProtocols.Tls10Client) != 0;
			case MSI.TlsProtocolCode.Tls11:
				return (supportedProtocols & MSI.TlsProtocols.Tls11Client) != 0;
			case MSI.TlsProtocolCode.Tls12:
				return (supportedProtocols & MSI.TlsProtocols.Tls12Client) != 0;
			default:
				return false;
			}
		}

		public static bool IsTls10OrNewer (MSI.TlsProtocolCode protocol)
		{
			return IsTls10OrNewer ((short)protocol);
		}

		public static bool IsTls10OrNewer (short code)
		{
			return (code >> 8) == 3 && (code & 0x00ff) > 1;
		}

		public static bool IsTls12OrNewer (MSI.TlsProtocolCode protocol)
		{
			return IsTls12OrNewer ((short)protocol);
		}

		public static bool IsTls12OrNewer (short code)
		{
			return (code >> 8) == 3 && (code & 0x00ff) >= 3;
		}

		#endregion

		#region Client Configuration

		public string TargetHost {
			get;
			private set;
		}

		#endregion

		#region Common Configuration

		internal MX.X509Certificate Certificate {
			get;
			private set;
		}

		internal AsymmetricAlgorithm PrivateKey {
			get;
			private set;
		}

		public bool HasCredentials {
			get { return Certificate != null && PrivateKey != null; }
		}

		public void SetCertificate (MX.X509Certificate certificate, AsymmetricAlgorithm privateKey)
		{
			Certificate = certificate;
			#if !BOOTSTRAP_BASIC
			if (PrivateKey != null && PrivateKey != privateKey)
				PrivateKey.Dispose ();
			#endif
			PrivateKey = privateKey;
		}

		#endregion

		protected override void Clear ()
		{
			PrivateKey = null;
			Certificate = null;
		}
	}
}

