namespace Mono.Security.NewTls.TestFramework
{
	public interface IClientAndServerParameters : ICommonConnectionParameters
	{
		IClientParameters ClientParameters {
			get;
		}

		IServerParameters ServerParameters {
			get;
		}
	}
}

