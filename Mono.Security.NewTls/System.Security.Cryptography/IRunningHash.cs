#if INSIDE_MONO_SECURITY
namespace System.Security.Cryptography
{
	internal interface IRunningHash
	{
		void TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount);

		byte[] GetRunningHash ();

		void Clear ();
	}
}
#endif
