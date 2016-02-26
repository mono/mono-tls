//
// SettingsProvider.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Collections.Generic;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	public class SettingsProvider
	{
		readonly UserSettings settings;
		bool? askForClientCertificate;

		public virtual UserSettings UserSettings {
			get { return settings; }
		}

		public virtual bool EnableDebugging {
			get { return settings.EnableDebugging; }
		}

		public virtual bool AskForClientCertificate {
			get {
				#if FIXME
				return askForClientCertificate ?? settings.Settings.AskForClientCertificate ?? RequireClientCertificate;
				#else
				return askForClientCertificate ?? RequireClientCertificate;
				#endif
			}
		}

		public virtual bool RequireClientCertificate {
			get {
				#if FIXME
				return settings.Settings.RequireClientCertificate ?? false;
				#else
				return false;
				#endif
			}
		}

		protected internal virtual void Initialize (ITlsContext ctx)
		{
			if (ctx.AskForClientCertificate != null)
				askForClientCertificate = ctx.AskForClientCertificate.Value;
		}

		public virtual ICollection<CipherSuiteCode> RequestedCiphers {
			get { return settings.Settings.EnabledCiphers; }
		}

		public virtual bool HasClientSignatureParameters {
			get { return settings.HasSignatureParameters; }
		}

		public virtual bool HasClientCertificateParameters {
			get { return settings.HasClientCertificateParameters; }
		}

		public virtual SignatureParameters ClientSignatureParameters {
			get { return settings.SignatureParameters; }
		}

		public virtual ClientCertificateParameters ClientCertificateParameters {
			get { return settings.ClientCertificateParameters; }
		}

		#region Instrumentation override only

		public virtual RenegotiationFlags? ClientRenegotiationFlags {
			get { return null; }
		}

		public virtual RenegotiationFlags? ServerRenegotiationFlags {
			get { return null; }
		}

		#endregion

		public SettingsProvider (UserSettings settings)
		{
			this.settings = settings;
		}
	}
}

