namespace Mono.Security.NewTls.EC
{
	internal abstract class X9ECParametersHolder
	{
		private X9ECParameters parameters;

		public X9ECParameters Parameters {
			get {
				if (parameters == null) {
					parameters = CreateParameters ();
				}

				return parameters;
			}
		}

		protected abstract X9ECParameters CreateParameters ();
	}
}
