using System;
using System.Net.Security;
using Mono.Security.Interface;

namespace Mono.Security.Protocol.NewTls
{
	using Cipher;
	#if INSTRUMENTATION
	using Instrumentation;
	#endif

	public class TlsSettings : MonoTlsSettings
	{
		#region Server Configuration

		bool askForCert;
		bool requireCert;

		public bool AskForClientCertificate {
			get { return askForCert || requireCert; }
			set { askForCert = value; }
		}

		public bool RequireClientCertificate {
			get { return requireCert; }
			set {
				requireCert = value;
				if (value)
					askForCert = true;
			}
		}

		[CLSCompliant (false)]
		public CipherSuiteCollection RequestedCiphers {
			get; set;
		}

		ClientCertificateParameters clientCertParams;

		public bool HasClientCertificateParameters {
			get { return clientCertParams != null; }
		}

		public ClientCertificateParameters ClientCertificateParameters {
			get {
				if (clientCertParams == null)
					clientCertParams = new ClientCertificateParameters ();
				return clientCertParams;
			}
			set {
				clientCertParams = value;
			}
		}

		public bool MartinHack_TriggerRenegotiationOnFinish {
			get; set;
		}

		public ClientCertValidationCallback ClientCertValidationCallback {
			get; set;
		}

		public bool EnableDebugging {
			get; set;
		}

		#endregion

		#region Provided by the server

		[CLSCompliant (false)]
		public TlsConnectionInfo ConnectionInfo {
			get;
			internal set;
		}

		#endregion

		#if INSTRUMENTATION

		public InstrumentCollection Instrumentation {
			get; set;
		}

		#endif
	}
}

