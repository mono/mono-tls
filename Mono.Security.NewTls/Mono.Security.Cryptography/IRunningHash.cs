namespace Mono.Security.Cryptography
{
	public interface IRunningHash
	{
		void TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount);

		byte[] GetRunningHash ();

		void Clear ();
	}
}
