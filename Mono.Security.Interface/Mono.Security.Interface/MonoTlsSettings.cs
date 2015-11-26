//
// MonoTlsSettings.cs
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
using System.Threading;
using System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Interface
{
	public sealed class MonoTlsSettings
	{
		public MonoRemoteCertificateValidationCallback RemoteCertificateValidationCallback {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public MonoLocalCertificateSelectionCallback ClientCertificateSelectionCallback {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public bool CheckCertificateName {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public bool CheckCertificateRevocationStatus {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public bool UseServicePointManagerCallback {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public bool SkipSystemValidators {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public bool CallbackNeedsCertificateChain {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		/*
		 * This is only supported if CertificateValidationHelper.SupportsTrustAnchors is true.
		 */
		public X509CertificateCollection TrustAnchors {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public object UserSettings {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		/*
		 * If you set this here, then it will override 'ServicePointManager.SecurityProtocol'.
		 */
		public TlsProtocols? EnabledProtocols {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public MonoTlsSettings ()
		{
			throw new NotImplementedException ();
		}

		public static MonoTlsSettings DefaultSettings {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public static MonoTlsSettings CopyDefaultSettings ()
		{
			throw new NotImplementedException ();
		}
	}
}

