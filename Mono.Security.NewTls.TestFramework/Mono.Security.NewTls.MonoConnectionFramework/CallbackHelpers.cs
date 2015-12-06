//
// CallbackHelpers.cs
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
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using MSI = Mono.Security.Interface;

using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Server;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	static class CallbackHelpers
	{
		internal static SslProtocols GetSslProtocol ()
		{
			return (SslProtocols)ServicePointManager.SecurityProtocol;
		}

		internal static RemoteCertificateValidationCallback GetServerValidationCallback (ConnectionParameters parameters)
		{
			var validator = parameters.ServerCertificateValidator;
			if (validator == null)
				return null;

			return ((CertificateValidator)validator).ValidationCallback;
		}

		internal static RemoteCertificateValidationCallback GetClientValidationCallback (ConnectionParameters parameters)
		{
			var validator = parameters.ClientCertificateValidator;
			if (validator == null)
				return null;

			return ((CertificateValidator)validator).ValidationCallback;
		}

		internal static X509CertificateCollection GetClientCertificates (ConnectionParameters parameters)
		{
			if (parameters.ClientCertificate == null)
				return null;

			var clientCertificateCollection = new X509CertificateCollection ();
			var certificate = parameters.ClientCertificate;
			clientCertificateCollection.Add (certificate);

			return clientCertificateCollection;
		}

		internal static void AddCertificateValidator (MSI.MonoTlsSettings settings, CertificateValidator validator)
		{
			if (validator == null)
				return;

			settings.RemoteCertificateValidationCallback = (s, c, ch, e) => {
				return validator.ValidationCallback (s, c, ch, (SslPolicyErrors)e);
			};
		}

		internal static void AddCertificateSelector (MSI.MonoTlsSettings settings, CertificateSelector selector)
		{
			if (selector == null)
				return;

			settings.ClientCertificateSelectionCallback = (t, lc, rc, ai) => {
				return selector.SelectionCallback (null, t, lc, rc, ai);
			};
		}
	}
}

