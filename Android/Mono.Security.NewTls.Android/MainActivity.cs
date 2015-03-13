using System;

using Android.App;
using Android.OS;

namespace Mono.Security.NewTls.Android
{
	using Xamarin.Forms;
	using Xamarin.Forms.Platform.Android;
	using Xamarin.AsyncTests;
	using Xamarin.AsyncTests.Framework;
	using Xamarin.AsyncTests.Portable;
	using Xamarin.AsyncTests.Mobile;

	[Activity (Label = "Mono.Security.NewTls.Android", MainLauncher = true)]
	public class MainActivity : FormsApplicationActivity
	{
		public TestFramework Framework {
			get;
			private set;
		}

		protected override void OnCreate (Bundle bundle)
		{
			base.OnCreate (bundle);

			Forms.Init (this, bundle);

			Framework = TestFramework.GetLocalFramework (typeof(MainActivity).Assembly);

			LoadApplication (new MobileTestApp (Framework));
		}
	}
}

