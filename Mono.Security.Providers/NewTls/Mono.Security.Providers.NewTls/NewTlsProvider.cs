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
using PrebuiltSystem::System.Security.Authentication;
using Mono.Security.NewTls;
#if PREBUILT_MSI
using MSI = PrebuiltSystem::Mono.Security.Interface;
#else
using MSI = Mono.Security.Interface;
#endif
using PrebuiltSystem::Mono.Net.Security;

using MX = Mono.Security.X509;
using PSSCX = PrebuiltSystem::System.Security.Cryptography.X509Certificates;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace Mono.Security.Providers.NewTls
{
	public class NewTlsProvider : MSI.MonoTlsProvider
	{
		static readonly Guid id = new Guid ("e5ff34f1-8b7a-4aa6-aff9-24719d709693");

		public override Guid ID {
			get { return id; }
		}

		public override string Name {
			get { return "newtls"; }
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

		public override SslProtocols SupportedProtocols {
			get { return SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls; }
		}

		public override MSI.MonoSslStream CreateSslStream (
			Stream innerStream, bool leaveInnerStreamOpen,
			MSI.MonoTlsSettings settings = null)
		{
			return MonoNewTlsStreamFactory.CreateSslStream (innerStream, leaveInnerStreamOpen, this, settings);
		}

		public override MSI.IMonoTlsContext CreateTlsContext (
			string hostname, bool serverMode, MSI.TlsProtocols protocolFlags,
			SSCX.X509Certificate serverCertificate, PSSCX.X509CertificateCollection clientCertificates,
			bool remoteCertRequired, MSI.MonoEncryptionPolicy encryptionPolicy,
			MSI.MonoTlsSettings settings)
		{
			TlsConfiguration config;
			if (serverMode) {
				var cert = (PSSCX.X509Certificate2)serverCertificate;
				var monoCert = new MX.X509Certificate (cert.RawData);
				config = new TlsConfiguration ((TlsProtocols)protocolFlags, (MSI.MonoTlsSettings)settings, monoCert, cert.PrivateKey);
				if (remoteCertRequired)
					config.AskForClientCertificate = true;
			} else {
				config = new TlsConfiguration ((TlsProtocols)protocolFlags, (MSI.MonoTlsSettings)settings, hostname);
			}

			return new TlsContextWrapper (config, serverMode);
		}

		public static bool IsNewTlsStream (MSI.MonoSslStream stream)
		{
			return stream is MonoSslStreamImpl;
		}

		public static MonoNewTlsStream GetNewTlsStream (MSI.MonoSslStream stream)
		{
			return ((MonoSslStreamImpl)stream).Impl;
		}
	}
}

