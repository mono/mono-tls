//
// RenegotiationInstrumentParameters.cs
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
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestFramework
{
	using TestFeatures;

	[RenegotiationInstrumentParameters]
	public class RenegotiationInstrumentParameters : ConnectionInstrumentParameters
	{
		public RenegotiationInstrumentType Type {
			get;
			private set;
		}

		public RenegotiationInstrumentParameters (InstrumentationCategory category, RenegotiationInstrumentType type, string identifier, IServerCertificate certificate)
			: base (category, identifier, certificate)
		{
			Type = type;
		}

		protected RenegotiationInstrumentParameters (RenegotiationInstrumentParameters other)
			: base (other)
		{
			Type = other.Type;
			ClientRenegotiationFlags = other.ClientRenegotiationFlags;
			ServerRenegotiationFlags = other.ServerRenegotiationFlags;
			RequestServerRenegotiation = other.RequestServerRenegotiation;
			RequestClientRenegotiation = other.RequestClientRenegotiation;
			QueueServerReadFirst = other.QueueServerReadFirst;
			ServerWriteDuringClientRenegotiation = other.ServerWriteDuringClientRenegotiation;
			NeedCustomCertificateSelectionCallback = other.NeedCustomCertificateSelectionCallback;
		}

		public override ConnectionParameters DeepClone ()
		{
			return new RenegotiationInstrumentParameters (this);
		}

		public RenegotiationFlags? ClientRenegotiationFlags {
			get; set;
		}

		public RenegotiationFlags? ServerRenegotiationFlags {
			get; set;
		}

		public bool RequestServerRenegotiation {
			get; set;
		}

		public bool RequestClientRenegotiation {
			get; set;
		}

		public bool QueueServerReadFirst {
			get; set;
		}

		public bool ServerWriteDuringClientRenegotiation {
			get; set;
		}

		public bool NeedCustomCertificateSelectionCallback {
			get; set;
		}
	}
}

