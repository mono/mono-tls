using System;
using System.Threading;
using System.Collections.Generic;
using System.Net.Security;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	using Cipher;

	public class TlsSettings : MonoTlsSettings
	{
		public TlsSettings ()
		{
		}

		public TlsSettings (UserSettings settings)
		{
			this.settings = settings;
		}

		UserSettings settings;

		public UserSettings UserSettings {
			get {
				if (settings == null)
					Interlocked.CompareExchange<UserSettings> (ref settings, new UserSettings (), null);
				return settings;
			}
		}

		#region Provided by the server

		[CLSCompliant (false)]
		public TlsConnectionInfo ConnectionInfo {
			get;
			internal set;
		}

		#endregion

		#if INSTRUMENTATION

		public Instrumentation Instrumentation {
			get; set;
		}

		#endif
	}
}

