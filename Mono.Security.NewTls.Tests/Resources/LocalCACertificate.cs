using System;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	public class LocalCACertificate : ICertificateAsPEM
	{
		public byte[] Data {
			get;
			private set;
		}

		internal LocalCACertificate ()
		{
			Data = ResourceManager.ReadResource ("CA.Hamiller-Tube-CA.pem");
		}
	}
}

