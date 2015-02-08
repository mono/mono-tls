using System;
using System.Net;

using Android.App;
using Android.Content;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Android.OS;

namespace DroidTest
{
	[Activity (Label = "DroidTest", MainLauncher = true, Icon = "@drawable/icon")]
	public class MainActivity : Activity
	{
		const string Address = "https://www.google.com/";

		int count = 1;

		protected override void OnCreate (Bundle bundle)
		{
			base.OnCreate (bundle);

			// Set our view from the "main" layout resource
			SetContentView (Resource.Layout.Main);

			// Get our button from the layout resource,
			// and attach an event to it
			Button button = FindViewById<Button> (Resource.Id.myButton);
			
			button.Click += delegate {
				Test();
			};
		}

		void Test ()
		{
			var request = (HttpWebRequest)WebRequest.Create(Address);
			var response = (HttpWebResponse)request.GetResponse();
			Console.WriteLine("RESPONSE: {0} {1}", response.StatusCode, response.StatusDescription);
		}
	}
}


