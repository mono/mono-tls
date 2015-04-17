//
// NewTlsProvider.cs
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
extern alias NewSystemSource;
extern alias PrebuiltSystem;

using System;
using System.IO;
using PrebuiltSystem::System.Net;
using PrebuiltSystem::System.Net.Security;
using Mono.Security.NewTls;
#if PREBUILT_MSI
using PrebuiltSystem::Mono.Security.Interface;
#else
using Mono.Security.Interface;
#endif
using PrebuiltSystem::Mono.Net.Security;

using MX = Mono.Security.X509;
using PSSCX = PrebuiltSystem::System.Security.Cryptography.X509Certificates;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Providers.NewTls
{
	/*
	 * This provider only uses the public .NET APIs from System.dll.
	 * 
	 * It is primarily intended for testing.
	 */
	public class NewTlsProvider : MonoTlsProvider
	{
		public override bool SupportsHttps {
			get { return false; }
		}

		public override bool SupportsSslStream {
			get { return true; }
		}

		public override bool SupportsMonoExtensions {
			get { return true; }
		}

		public override bool SupportsTlsContext {
			get { return true; }
		}

		public override bool IsHttpsStream (Stream stream)
		{
			return false;
		}

#pragma warning disable 618

		public override IMonoHttpsStream GetHttpsStream (Stream stream)
		{
			throw new InvalidOperationException ();
		}

		public override IMonoHttpsStream CreateHttpsClientStream (
			Stream innerStream, HttpWebRequest request, byte[] buffer)
		{
			throw new NotSupportedException ();
		}

#pragma warning restore 618

		public override MonoSslStream CreateSslStream (
			Stream innerStream, bool leaveInnerStreamOpen,
			CertificateValidationHelper validationHelper,
			MonoTlsSettings settings = null)
		{
			return MonoNewTlsStreamFactory.CreateSslStream (innerStream, leaveInnerStreamOpen, validationHelper, settings);
		}

		public override IMonoTlsContext CreateTlsContext (
			string hostname, bool serverMode, TlsProtocols protocolFlags,
			SSCX.X509Certificate serverCertificate, PSSCX.X509CertificateCollection clientCertificates,
			bool remoteCertRequired, MonoEncryptionPolicy encryptionPolicy,
			CertificateValidationHelper certificateValidationHelper,
			MonoTlsSettings settings)
		{
			TlsConfiguration config;
			if (serverMode) {
				var cert = (PSSCX.X509Certificate2)serverCertificate;
				var monoCert = new MX.X509Certificate (cert.RawData);
				config = new TlsConfiguration ((TlsProtocols)protocolFlags, (TlsSettings)settings, monoCert, cert.PrivateKey);
			} else {
				config = new TlsConfiguration ((TlsProtocols)protocolFlags, (TlsSettings)settings, hostname);
				config.CertificateValidationHelper = certificateValidationHelper;
			}

			return new TlsContextWrapper (config);
		}

		public static MonoNewTlsStream GetNewTlsStream (MonoSslStream stream)
		{
			return ((MonoSslStreamImpl)stream).Impl;
		}
	}
}

