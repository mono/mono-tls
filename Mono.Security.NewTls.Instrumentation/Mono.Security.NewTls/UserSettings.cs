﻿//
// UserSettings.cs
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
	public sealed class UserSettings
	{
		public UserSettings (MonoTlsSettings settings)
		{
			this.settings = settings;
			settings.UserSettings = this;
		}

		public MonoTlsSettings Settings {
			get { return settings; }
		}

		MonoTlsSettings settings;

		ClientCertificateParameters clientCertParams;
		SignatureParameters signatureParameters;
		bool hasSignatureParameters;
		bool hasClientCertParameters;

		public bool EnableDebugging {
			get; set;
		}

		public bool HasClientCertificateParameters {
			get { return hasClientCertParameters; }
		}

		public bool HasSignatureParameters {
			get { return hasSignatureParameters; }
		}

		public ClientCertificateParameters ClientCertificateParameters {
			get {
				if (!hasClientCertParameters)
					throw new InvalidOperationException ();
				return clientCertParams;
			}
			set {
				clientCertParams = value;
				hasClientCertParameters = true;
			}
		}

		public SignatureParameters SignatureParameters {
			get {
				if (!hasSignatureParameters)
					throw new InvalidOperationException ();
				return signatureParameters;
			}
			set {
				signatureParameters = value;
				hasSignatureParameters = true;
			}
		}

		public NamedCurve? NamedCurve {
			get; set;
		}

		#if INSTRUMENTATION

		public Instrumentation Instrumentation {
			get; set;
		}

		#endif
	}
}

