using System;

namespace System.Collections
{
	public abstract class CollectionBase : IList
	{
		protected CollectionBase ()
		{
			throw new NotImplementedException ();
		}

		protected CollectionBase (int capacity)
		{
			throw new NotImplementedException ();
		}

		public int Capacity {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public int Count {
			get { throw new NotImplementedException (); }
		}

		public void Clear ()
		{
			throw new NotImplementedException ();
		}

		public void RemoveAt (int index)
		{
			throw new NotImplementedException ();
		}

		bool IList.IsReadOnly {
			get { throw new NotImplementedException (); }
		}

		bool IList.IsFixedSize {
			get { throw new NotImplementedException (); }
		}

		bool ICollection.IsSynchronized {
			get { throw new NotImplementedException (); }
		}

		Object ICollection.SyncRoot {
			get { throw new NotImplementedException (); }
		}

		void ICollection.CopyTo (Array array, int index)
		{
			throw new NotImplementedException ();
		}

		object IList.this [int index] {
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		bool IList.Contains (Object value)
		{
			throw new NotImplementedException ();
		}

		int IList.Add (Object value)
		{
			throw new NotImplementedException ();
		}
       
		void IList.Remove (Object value)
		{
			throw new NotImplementedException ();
		}

		int IList.IndexOf (Object value)
		{
			throw new NotImplementedException ();
		}

		void IList.Insert (int index, Object value)
		{
			throw new NotImplementedException ();
		}

		public IEnumerator GetEnumerator ()
		{
			throw new NotImplementedException ();
		}
	}
}
