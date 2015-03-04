//
// NewTlsTestSuite.cs
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

[assembly: AsyncTestSuite (typeof (Mono.Security.NewTls.Tests.NewTlsTestFeatures))]

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	public class NotWorkingAttribute : TestFeatureAttribute
	{
		public override TestFeature Feature {
			get { return NewTlsTestFeatures.NotWorking; }
		}
	}

	public class WorkAttribute : TestCategoryAttribute
	{
		public override TestCategory Category {
			get { return NewTlsTestFeatures.Work; }
		}
	}

	public class NewTlsTestFeatures : ITestConfigurationProvider
	{
		public static readonly NewTlsTestFeatures Instance;

		public static readonly TestCategory Work = new TestCategory ("Work");
		public static readonly TestFeature Hello = new TestFeature ("Hello", "Hello World");
		public static readonly TestFeature NotWorking = new TestFeature ("NotWorking", "Not Working");

		public static readonly TestFeature MonoCryptoProvider = new TestFeature (
			"MonoCryptoProvider", "Use Mono.Security as crypto provider", true);
		public static readonly TestFeature OpenSslCryptoProvider = new TestFeature (
			"OpenSslCryptoProvider", "Use OpenSSL as crypto provider", () => IsOpenSslSupported ());

		static bool IsOpenSslSupported ()
		{
			var provider = DependencyInjector.Get<ICryptoProvider> ();
			return provider.IsSupported (CryptoTestHostType.OpenSsl, true);
		}

		static NewTlsTestFeatures ()
		{
			Instance = new NewTlsTestFeatures ();
		}

		public string Name {
			get { return "Mono.Security.NewTls.Tests"; }
		}

		public IEnumerable<TestFeature> Features {
			get {
				yield return Hello;
				yield return NotWorking;
				yield return MonoCryptoProvider;
				yield return OpenSslCryptoProvider;
			}
		}

		public IEnumerable<TestCategory> Categories {
			get {
				yield return Work;
			}
		}

		[AttributeUsage (AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = false)]
		public class SelectCryptoProvider : TestParameterAttribute, ITestParameterSource<CryptoTestHostType>
		{
			public SelectCryptoProvider (string filter = null, TestFlags flags = TestFlags.Hidden)
				: base (filter, flags)
			{
			}

			public IEnumerable<CryptoTestHostType> GetParameters (TestContext ctx, string filter)
			{
				if (filter != null) {
					if (filter.Equals ("mono"))
						yield return CryptoTestHostType.Mono;
					else if (filter.Equals ("openssl"))
						yield return CryptoTestHostType.OpenSsl;
					yield break;
				}

				if (ctx.IsEnabled (MonoCryptoProvider))
					yield return CryptoTestHostType.Mono;
				if (ctx.IsEnabled (OpenSslCryptoProvider))
					yield return CryptoTestHostType.OpenSsl;
			}
		}


	}

}

