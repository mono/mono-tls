using System;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public abstract class ClientAndServerParameters : ConnectionParameters, IClientAndServerParameters, ICloneable
	{
		protected ClientAndServerParameters (string identifier)
			: base (identifier)
		{
		}

		object ICloneable.Clone ()
		{
			return DeepClone ();
		}

		public abstract IClientParameters ClientParameters {
			get;
		}

		public abstract IServerParameters ServerParameters {
			get;
		}

		public abstract ClientAndServerParameters DeepClone ();

		public static ClientAndServerParameters Create (ClientParameters clientParameters, ServerParameters serverParameters)
		{
			return new SimpleClientAndServerParameters (clientParameters, serverParameters);
		}

		class SimpleClientAndServerParameters : ClientAndServerParameters
		{
			readonly ClientParameters clientParameters;
			readonly ServerParameters serverParameters;

			public SimpleClientAndServerParameters (ClientParameters clientParameters, ServerParameters serverParameters)
				: base (clientParameters.Identifier + ":" + serverParameters.Identifier)
			{
				this.clientParameters= clientParameters;
				this.serverParameters = serverParameters;
			}

			public override ClientAndServerParameters DeepClone ()
			{
				return new SimpleClientAndServerParameters (clientParameters.DeepClone (), serverParameters.DeepClone ());
			}

			public override IClientParameters ClientParameters {
				get { return clientParameters; }
			}

			public override IServerParameters ServerParameters {
				get { return serverParameters; }
			}
		}
	}
}

