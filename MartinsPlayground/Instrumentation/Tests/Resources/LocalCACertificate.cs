﻿using System;

namespace Mono.Security.Instrumentation.Resources
{
	using Framework;

	public class LocalCACertificate : CertificateAsPEM
	{
		internal LocalCACertificate ()
			: base (ResourceManager.ReadResource ("CA.Hamiller-Tube-CA.pem"))
		{
		}
	}
}

