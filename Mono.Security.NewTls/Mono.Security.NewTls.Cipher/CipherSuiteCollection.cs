using System;
using System.Collections;
using System.Collections.Generic;

namespace Mono.Security.NewTls.Cipher
{
	[CLSCompliant (false)]
	public class CipherSuiteCollection : IList<CipherSuiteCode>
	{
		public TlsProtocolCode Protocol {
			get;
			private set;
		}

		List<CipherSuiteCode> innerList;

		public CipherSuiteCollection (TlsProtocolCode protocol, ICollection<CipherSuiteCode> codes)
		{
			Protocol = protocol;
			innerList = new List<CipherSuiteCode> ();
			if (codes != null) {
				foreach (var code in codes)
					Add (code);
			}
		}

		void ValidateCipher (CipherSuiteCode code)
		{
			if (!CipherSuiteFactory.IsCipherSupported (Protocol, code))
				throw new TlsException (AlertDescription.InsuficientSecurity, "Unsupported cipher suite: {0}", code);
		}

		internal void AddSCSV ()
		{
			if (!innerList.Contains (CipherSuiteCode.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
				innerList.Add (CipherSuiteCode.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
		}

		public CipherSuiteCode[] ToArray ()
		{
			return innerList.ToArray ();
		}

		public CipherSuiteCollection Clone ()
		{
			return new CipherSuiteCollection (Protocol, innerList.ToArray ());
		}

		#region IList implementation

		public int IndexOf (CipherSuiteCode item)
		{
			return innerList.IndexOf (item);
		}

		public void Insert (int index, CipherSuiteCode code)
		{
			ValidateCipher (code);
			innerList.Insert (index, code);
		}

		public void RemoveAt (int index)
		{
			innerList.RemoveAt (index);
		}

		public CipherSuiteCode this [int index] {
			get {
				return innerList [index];
			}
			set {
				ValidateCipher (value);
				innerList [index] = value;
			}
		}

		#endregion

		#region ICollection implementation

		public void Add (CipherSuiteCode code)
		{
			ValidateCipher (code);
			innerList.Add (code);
		}

		public void Clear ()
		{
			innerList.Clear ();
		}

		public bool Contains (CipherSuiteCode code)
		{
			return innerList.Contains (code);
		}

		public void CopyTo (CipherSuiteCode[] array, int arrayIndex)
		{
			innerList.CopyTo (array, arrayIndex);
		}

		public bool Remove (CipherSuiteCode item)
		{
			return innerList.Remove (item);
		}

		public int Count {
			get { return innerList.Count; }
		}

		public bool IsReadOnly {
			get { return false; }
		}

		#endregion

		#region IEnumerable implementation

		public IEnumerator<CipherSuiteCode> GetEnumerator ()
		{
			return innerList.GetEnumerator ();
		}

		#endregion

		#region IEnumerable implementation

		IEnumerator IEnumerable.GetEnumerator ()
		{
			return GetEnumerator ();
		}

		#endregion
	}
}

