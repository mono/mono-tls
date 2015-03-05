using System;
using System.Threading;
using System.Threading.Tasks;

using Android.App;
using Android.Content;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using Android.OS;

namespace Mono.Security.NewTls.Android
{
	[Activity (Label = "Mono.Security.NewTls.Android", MainLauncher = true, Icon = "@drawable/icon")]
	public class MainActivity : Activity
	{
		TestRunner runner;
		TextView text;

		protected override void OnCreate (Bundle bundle)
		{
			base.OnCreate (bundle);

			SetContentView (Resource.Layout.Main);
			text = FindViewById<TextView> (Resource.Id.textView);

			runner = new TestRunner ();
			runner.LogEvent += (sender, e) => {
				RunOnUiThread (() => text.Text = e);
			};
			Run ();
		}

		async void Run ()
		{
			while (true) {
				text.Text = "Server running.";
				await runner.RunServer ();
				text.Text = "Server done.";

				await Task.Delay (2500);
			}
		}
	}
}


