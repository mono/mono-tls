using System;
using System.IO;
using System.Threading;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Globalization;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.ComponentModel;
using System.Diagnostics;

namespace System.Security.Authentication
{
    [Flags]
    public enum SslProtocols
    {
        None = 0,
        Ssl2 = SchProtocols.Ssl2,
        Ssl3 = SchProtocols.Ssl3,
        Tls = SchProtocols.Tls10,
        Tls11 = SchProtocols.Tls11,
        Tls12 = SchProtocols.Tls12,
        Default = Ssl3 | Tls
    }
}

namespace System.Net {
    internal enum Endianness {
        Network             = 0x00,
        Native              = 0x10,
    }
    internal enum CredentialUse {
        Inbound             = 0x1,
        Outbound            = 0x2,
        Both                = 0x3,
    }
    internal enum ContextAttribute {
        //
        // look into <sspi.h> and <schannel.h>
        //
        Sizes               = 0x00,
        Names               = 0x01,
        Lifespan            = 0x02,
        DceInfo             = 0x03,
        StreamSizes         = 0x04,
        //KeyInfo             = 0x05, must not be used, see ConnectionInfo instead
        Authority           = 0x06,
        // SECPKG_ATTR_PROTO_INFO          = 7,
        // SECPKG_ATTR_PASSWORD_EXPIRY     = 8,
        // SECPKG_ATTR_SESSION_KEY         = 9,
        PackageInfo         = 0x0A,
        // SECPKG_ATTR_USER_FLAGS          = 11,
        NegotiationInfo    = 0x0C,
        // SECPKG_ATTR_NATIVE_NAMES        = 13,
        // SECPKG_ATTR_FLAGS               = 14,
        // SECPKG_ATTR_USE_VALIDATED       = 15,
        // SECPKG_ATTR_CREDENTIAL_NAME     = 16,
        // SECPKG_ATTR_TARGET_INFORMATION  = 17,
        // SECPKG_ATTR_ACCESS_TOKEN        = 18,
        // SECPKG_ATTR_TARGET              = 19,
        // SECPKG_ATTR_AUTHENTICATION_ID   = 20,
        UniqueBindings      = 0x19,
        EndpointBindings    = 0x1A,
        ClientSpecifiedSpn  = 0x1B, // SECPKG_ATTR_CLIENT_SPECIFIED_TARGET = 27
        RemoteCertificate   = 0x53,
        LocalCertificate    = 0x54,
        RootStore           = 0x55,
        IssuerListInfoEx    = 0x59,
        ConnectionInfo      = 0x5A,
        // SECPKG_ATTR_EAP_KEY_BLOCK        0x5b   // returns SecPkgContext_EapKeyBlock  
        // SECPKG_ATTR_MAPPED_CRED_ATTR     0x5c   // returns SecPkgContext_MappedCredAttr  
        // SECPKG_ATTR_SESSION_INFO         0x5d   // returns SecPkgContext_SessionInfo  
        // SECPKG_ATTR_APP_DATA             0x5e   // sets/returns SecPkgContext_SessionAppData  
        // SECPKG_ATTR_REMOTE_CERTIFICATES  0x5F   // returns SecPkgContext_Certificates  
        // SECPKG_ATTR_CLIENT_CERT_POLICY   0x60   // sets    SecPkgCred_ClientCertCtlPolicy  
        // SECPKG_ATTR_CC_POLICY_RESULT     0x61   // returns SecPkgContext_ClientCertPolicyResult  
        // SECPKG_ATTR_USE_NCRYPT           0x62   // Sets the CRED_FLAG_USE_NCRYPT_PROVIDER FLAG on cred group  
        // SECPKG_ATTR_LOCAL_CERT_INFO      0x63   // returns SecPkgContext_CertInfo  
        // SECPKG_ATTR_CIPHER_INFO          0x64   // returns new CNG SecPkgContext_CipherInfo  
        // SECPKG_ATTR_EAP_PRF_INFO         0x65   // sets    SecPkgContext_EapPrfInfo  
        // SECPKG_ATTR_SUPPORTED_SIGNATURES 0x66   // returns SecPkgContext_SupportedSignatures  
        // SECPKG_ATTR_REMOTE_CERT_CHAIN    0x67   // returns PCCERT_CONTEXT  
        UiInfo              = 0x68, // sets SEcPkgContext_UiInfo  
    }

    public abstract class TransportContext
    {
        public abstract ChannelBinding GetChannelBinding(ChannelBindingKind kind);
    }

    internal class SslStreamContext : TransportContext
    {
        internal SslStreamContext(SslStream sslStream)
        {
            GlobalLog.Assert(sslStream != null, "SslStreamContext..ctor(): Not expecting a null sslStream!");
            this.sslStream = sslStream;
        }

        public override ChannelBinding GetChannelBinding(ChannelBindingKind kind)
        {
            return sslStream.GetChannelBinding(kind);
        }

        private SslStream sslStream;
    }

    internal enum SecurityStatus
    {
        // Success / Informational
        OK                          =   0x00000000,
        ContinueNeeded              =   unchecked((int)0x00090312),
        CompleteNeeded              =   unchecked((int)0x00090313),
        CompAndContinue             =   unchecked((int)0x00090314),
        ContextExpired              =   unchecked((int)0x00090317),
        CredentialsNeeded           =   unchecked((int)0x00090320),
        Renegotiate                 =   unchecked((int)0x00090321),

        // Errors
        OutOfMemory                 =   unchecked((int)0x80090300),
        InvalidHandle               =   unchecked((int)0x80090301),
        Unsupported                 =   unchecked((int)0x80090302),
        TargetUnknown               =   unchecked((int)0x80090303),
        InternalError               =   unchecked((int)0x80090304),
        PackageNotFound             =   unchecked((int)0x80090305),
        NotOwner                    =   unchecked((int)0x80090306),
        CannotInstall               =   unchecked((int)0x80090307),
        InvalidToken                =   unchecked((int)0x80090308),
        CannotPack                  =   unchecked((int)0x80090309),
        QopNotSupported             =   unchecked((int)0x8009030A),
        NoImpersonation             =   unchecked((int)0x8009030B),
        LogonDenied                 =   unchecked((int)0x8009030C),
        UnknownCredentials          =   unchecked((int)0x8009030D),
        NoCredentials               =   unchecked((int)0x8009030E),
        MessageAltered              =   unchecked((int)0x8009030F),
        OutOfSequence               =   unchecked((int)0x80090310),
        NoAuthenticatingAuthority   =   unchecked((int)0x80090311),
        IncompleteMessage           =   unchecked((int)0x80090318),
        IncompleteCredentials       =   unchecked((int)0x80090320),
        BufferNotEnough             =   unchecked((int)0x80090321),
        WrongPrincipal              =   unchecked((int)0x80090322),
        TimeSkew                    =   unchecked((int)0x80090324),
        UntrustedRoot               =   unchecked((int)0x80090325),
        IllegalMessage              =   unchecked((int)0x80090326),
        CertUnknown                 =   unchecked((int)0x80090327),
        CertExpired                 =   unchecked((int)0x80090328),
        AlgorithmMismatch           =   unchecked((int)0x80090331),
        SecurityQosFailed           =   unchecked((int)0x80090332),
        SmartcardLogonRequired      =   unchecked((int)0x8009033E),
        UnsupportedPreauth          =   unchecked((int)0x80090343),
        BadBinding                  =   unchecked((int)0x80090346)
    }

    // Internal versions of the above delegates
    internal delegate bool RemoteCertValidationCallback(string host, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors);
    internal delegate X509Certificate LocalCertSelectionCallback(string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers);

    //
    // support class for Validation related stuff.
    //
    internal static class ValidationHelper {

        public static string [] EmptyArray = new string[0];

        internal static readonly char[]  InvalidMethodChars =
            new char[]{
            ' ',
            '\r',
            '\n',
            '\t'
        };

        // invalid characters that cannot be found in a valid method-verb or http header
        internal static readonly char[]  InvalidParamChars =
            new char[]{
            '(',
            ')',
            '<',
            '>',
            '@',
            ',',
            ';',
            ':',
            '\\',
            '"',
            '\'',
            '/',
            '[',
            ']',
            '?',
            '=',
            '{',
            '}',
            ' ',
            '\t',
            '\r',
            '\n'};

        public static string [] MakeEmptyArrayNull(string [] stringArray) {
            if ( stringArray == null || stringArray.Length == 0 ) {
                return null;
            } else {
                return stringArray;
            }
        }

        public static string MakeStringNull(string stringValue) {
            if ( stringValue == null || stringValue.Length == 0) {
                return null;
            } else {
                return stringValue;
            }
        }

        /*
        // Consider removing.
        public static string MakeStringEmpty(string stringValue) {
            if ( stringValue == null || stringValue.Length == 0) {
                return String.Empty;
            } else {
                return stringValue;
            }
        }
        */

        #if TRAVE
        /*
        // Consider removing.
        public static int HashCode(object objectValue) {
        if (objectValue == null) {
        return -1;
        } else {
        return objectValue.GetHashCode();
        }
        }
        */
        #endif

        public static string ExceptionMessage(Exception exception) {
            if (exception==null) {
                return string.Empty;
            }
            if (exception.InnerException==null) {
                return exception.Message;
            }
            return exception.Message + " (" + ExceptionMessage(exception.InnerException) + ")";
        }

        public static string ToString(object objectValue) {
            if (objectValue == null) {
                return "(null)";
            } else if (objectValue is string && ((string)objectValue).Length==0) {
                return "(string.empty)";
            } else if (objectValue is Exception) {
                return ExceptionMessage(objectValue as Exception);
            } else if (objectValue is IntPtr) {
                return "0x" + ((IntPtr)objectValue).ToString("x");
            } else {
                return objectValue.ToString();
            }
        }
        public static string HashString(object objectValue) {
            if (objectValue == null) {
                return "(null)";
            } else if (objectValue is string && ((string)objectValue).Length==0) {
                return "(string.empty)";
            } else {
                return objectValue.GetHashCode().ToString(NumberFormatInfo.InvariantInfo);
            }
        }

        public static bool IsInvalidHttpString(string stringValue) {
            return stringValue.IndexOfAny(InvalidParamChars)!=-1;
        }

        public static bool IsBlankString(string stringValue) {
            return stringValue==null || stringValue.Length==0;
        }

        /*
        // Consider removing.
        public static bool ValidateUInt32(long address) {
            // on false, API should throw new ArgumentOutOfRangeException("address");
            return address>=0x00000000 && address<=0xFFFFFFFF;
        }
        */

        public static bool ValidateTcpPort(int port) {
            // on false, API should throw new ArgumentOutOfRangeException("port");
            return port>=IPEndPoint.MinPort && port<=IPEndPoint.MaxPort;
        }

        public static bool ValidateRange(int actual, int fromAllowed, int toAllowed) {
            // on false, API should throw new ArgumentOutOfRangeException("argument");
            return actual>=fromAllowed && actual<=toAllowed;
        }

        /*
        // Consider removing.
        public static bool ValidateRange(long actual, long fromAllowed, long toAllowed) {
            // on false, API should throw new ArgumentOutOfRangeException("argument");
            return actual>=fromAllowed && actual<=toAllowed;
        }
        */

        // There are threading tricks a malicious app can use to create an ArraySegment with mismatched 
        // array/offset/count.  Copy locally and make sure they're valid before using them.
        internal static void ValidateSegment(ArraySegment<byte> segment) {
            if (segment == null || segment.Array == null) {
                throw new ArgumentNullException("segment");
            }
            // Length zero is explicitly allowed
            if (segment.Offset < 0 || segment.Count < 0 
                || segment.Count > (segment.Array.Length - segment.Offset)) {
                throw new ArgumentOutOfRangeException("segment");
            }
        }
    }
    internal class InternalException : SystemException
    {
        internal InternalException()
        {
            GlobalLog.Assert("InternalException thrown.");
        }

        internal InternalException(SerializationInfo serializationInfo, StreamingContext streamingContext) :
        base(serializationInfo, streamingContext)
        { }
    }

    internal static class NclUtilities
    {
        /// <devdoc>
        ///    <para>
        ///       Indicates true if the threadpool is low on threads,
        ///       in this case we need to refuse to start new requests,
        ///       and avoid blocking.
        ///    </para>
        /// </devdoc>
        internal static bool IsThreadPoolLow()
        {
            #if !FEATURE_PAL
            if (ComNetOS.IsAspNetServer)
            {
                return false;
            }
            #endif //!FEATURE_PAL

            int workerThreads, completionPortThreads;
            ThreadPool.GetAvailableThreads(out workerThreads, out completionPortThreads);

            #if !FEATURE_PAL
            return workerThreads < 2 || (completionPortThreads < 2);
            #else
            GlobalLog.Assert(completionPortThreads == 0, "completionPortThreads should be zero on the PAL");
            return workerThreads < 2;
            #endif //!FEATURE_PAL
        }


        internal static bool HasShutdownStarted
        {
            get
            {
                return Environment.HasShutdownStarted || AppDomain.CurrentDomain.IsFinalizingForUnload();
            }
        }

        #if !FEATURE_PAL
        // This only works for context-destroying errors.
        internal static bool IsCredentialFailure(SecurityStatus error)
        {
            return error == SecurityStatus.LogonDenied ||
                error == SecurityStatus.UnknownCredentials ||
                error == SecurityStatus.NoImpersonation ||
                error == SecurityStatus.NoAuthenticatingAuthority ||
                error == SecurityStatus.UntrustedRoot ||
                error == SecurityStatus.CertExpired ||
                error == SecurityStatus.SmartcardLogonRequired ||
                error == SecurityStatus.BadBinding;
        }

        // This only works for context-destroying errors.
        internal static bool IsClientFault(SecurityStatus error)
        {
            return error == SecurityStatus.InvalidToken ||
                error == SecurityStatus.CannotPack ||
                error == SecurityStatus.QopNotSupported ||
                error == SecurityStatus.NoCredentials ||
                error == SecurityStatus.MessageAltered ||
                error == SecurityStatus.OutOfSequence ||
                error == SecurityStatus.IncompleteMessage ||
                error == SecurityStatus.IncompleteCredentials ||
                error == SecurityStatus.WrongPrincipal ||
                error == SecurityStatus.TimeSkew ||
                error == SecurityStatus.IllegalMessage ||
                error == SecurityStatus.CertUnknown ||
                error == SecurityStatus.AlgorithmMismatch ||
                error == SecurityStatus.SecurityQosFailed ||
                error == SecurityStatus.UnsupportedPreauth;
        }
        #endif


        // ContextRelativeDemand
        // Allows easily demanding a permission against a given ExecutionContext.
        // Have requested the CLR to provide this method on ExecutionContext.
        private static volatile ContextCallback s_ContextRelativeDemandCallback;

        internal static ContextCallback ContextRelativeDemandCallback
        {
            get
            {
                if (s_ContextRelativeDemandCallback == null)
                    s_ContextRelativeDemandCallback = new ContextCallback(DemandCallback);
                return s_ContextRelativeDemandCallback;
            }
        }

        private static void DemandCallback(object state)
        {
            #if !MONO
            ((CodeAccessPermission) state).Demand();
            #endif
        }

        // This is for checking if a hostname probably refers to this machine without going to DNS.
        internal static bool GuessWhetherHostIsLoopback(string host)
        {
            string hostLower = host.ToLowerInvariant();
            if (hostLower == "localhost" || hostLower == "loopback")
            {
                return true;
            }

            #if !FEATURE_PAL
            IPGlobalProperties ip = IPGlobalProperties.InternalGetIPGlobalProperties();
            string hostnameLower = ip.HostName.ToLowerInvariant();
            return hostLower == hostnameLower || hostLower == hostnameLower + "." + ip.DomainName.ToLowerInvariant();
            #else
            return false;
            #endif
        }

        internal static bool IsFatal(Exception exception)
        {
            return exception != null && (exception is OutOfMemoryException || exception is StackOverflowException || exception is ThreadAbortException);
        }

        // Need a fast cached list of local addresses for internal use.
        private static volatile IPAddress[] _LocalAddresses;
        private static object _LocalAddressesLock;
        #if !MONO && !FEATURE_PAL
        private static volatile NetworkAddressChangePolled s_AddressChange;
        #endif

        #if !MONO && !FEATURE_PAL
        internal static IPAddress[] LocalAddresses
        {
            get
            {
                if (s_AddressChange != null && s_AddressChange.CheckAndReset())
                {
                    return (_LocalAddresses = GetLocalAddresses());
                }

                if (_LocalAddresses != null)
                {
                    return _LocalAddresses;
                }

                lock (LocalAddressesLock)
                {
                    if (_LocalAddresses != null)
                    {
                        return _LocalAddresses;
                    }

                    s_AddressChange = new NetworkAddressChangePolled();

                    return (_LocalAddresses = GetLocalAddresses());
                }
            }
        }

        private static IPAddress[] GetLocalAddresses()
        {
            IPAddress[] local;

            ArrayList collections = new ArrayList(16);
            int total = 0;

            SafeLocalFree buffer = null;
            GetAdaptersAddressesFlags gaaFlags = GetAdaptersAddressesFlags.SkipAnycast | GetAdaptersAddressesFlags.SkipMulticast |
                GetAdaptersAddressesFlags.SkipFriendlyName | GetAdaptersAddressesFlags.SkipDnsServer;
            uint size = 0;
            uint result = UnsafeNetInfoNativeMethods.GetAdaptersAddresses(AddressFamily.Unspecified, (uint)gaaFlags, IntPtr.Zero, SafeLocalFree.Zero, ref size);
            while (result == IpHelperErrors.ErrorBufferOverflow)
            {
                try
                {
                    buffer = SafeLocalFree.LocalAlloc((int)size);
                    result = UnsafeNetInfoNativeMethods.GetAdaptersAddresses(AddressFamily.Unspecified, (uint)gaaFlags, IntPtr.Zero, buffer, ref size);

                    if (result == IpHelperErrors.Success)
                    {
                        IntPtr nextAdapter = buffer.DangerousGetHandle();

                        while (nextAdapter != IntPtr.Zero)
                        {
                            IpAdapterAddresses adapterAddresses = (IpAdapterAddresses)Marshal.PtrToStructure(
                                nextAdapter, typeof(IpAdapterAddresses));

                            if (adapterAddresses.firstUnicastAddress != IntPtr.Zero)
                            {
                                UnicastIPAddressInformationCollection coll = 
                                    SystemUnicastIPAddressInformation.MarshalUnicastIpAddressInformationCollection(
                                        adapterAddresses.firstUnicastAddress);
                                total += coll.Count;
                                collections.Add(coll);
                            }

                            nextAdapter = adapterAddresses.next;
                        }
                    }
                }
                finally
                {
                    if (buffer != null)
                        buffer.Close();
                    buffer = null;
                }
            }

            if (result != IpHelperErrors.Success && result != IpHelperErrors.ErrorNoData)
            {
                throw new NetworkInformationException((int)result);
            }

            local = new IPAddress[total];
            uint i = 0;
            foreach (UnicastIPAddressInformationCollection coll in collections)
            {
                foreach (IPAddressInformation info in coll)
                {
                    local[i++] = info.Address;
                }
            }

            return local;
        }

        internal static bool IsAddressLocal(IPAddress ipAddress) {
            IPAddress[] localAddresses = NclUtilities.LocalAddresses;
            for (int i = 0; i < localAddresses.Length; i++)
            {
                if (ipAddress.Equals(localAddresses[i], false))
                {
                    return true;
                }
            }
            return false;
        }
        #else // !FEATURE_PAL
        private const int HostNameBufferLength = 256;
        internal static string _LocalDomainName;

        // Copied from the old version of DNS.cs
        // Returns a list of our local addresses by calling gethostbyname with null.
        //
        private static IPHostEntry GetLocalHost()
        {
        #if MONO
        return Dns.GetHostEntry (string.Empty);
        #else
        //
        // IPv6 Changes: If IPv6 is enabled, we can't simply use the
        //               old IPv4 gethostbyname(null). Instead we need
        //               to do a more complete lookup.
        //
        if (Socket.SupportsIPv6)
        {
            //
            // IPv6 enabled: use getaddrinfo() of the local host name
            // to obtain this information. Need to get the machines
            // name as well - do that here so that we don't need to
            // Assert DNS permissions.
            //
            StringBuilder hostname = new StringBuilder(HostNameBufferLength);
            SocketError errorCode =
                UnsafeNclNativeMethods.OSSOCK.gethostname(
                    hostname,
                    HostNameBufferLength);

            if (errorCode != SocketError.Success)
            {
                throw new SocketException();
            }

            return Dns.GetHostByName(hostname.ToString());
        }
        else
        {
            //
            // IPv6 disabled: use gethostbyname() to obtain information.
            //
            IntPtr nativePointer =
                UnsafeNclNativeMethods.OSSOCK.gethostbyname(
                    null);

            if (nativePointer == IntPtr.Zero)
            {
                throw new SocketException();
            }

            return Dns.NativeToHostEntry(nativePointer);
        }
        #endif
    } // GetLocalHost

    internal static IPAddress[] LocalAddresses
    {
        get
        {
            IPAddress[] local = _LocalAddresses;
            if (local != null)
            {
                return local;
            }

            lock (LocalAddressesLock)
            {
                local = _LocalAddresses;
                if (local != null)
                {
                    return local;
                }

                List<IPAddress> localList = new List<IPAddress>();

                try
                {
                    IPHostEntry hostEntry = GetLocalHost();
                    if (hostEntry != null)
                    {
                        if (hostEntry.HostName != null)
                        {
                            int dot = hostEntry.HostName.IndexOf('.');
                            if (dot != -1)
                            {
                                _LocalDomainName = hostEntry.HostName.Substring(dot);
                            }
                        }

                        IPAddress[] ipAddresses = hostEntry.AddressList;
                        if (ipAddresses != null)
                        {
                            foreach (IPAddress ipAddress in ipAddresses)
                            {
                                localList.Add(ipAddress);
                            }
                        }
                    }
                }
                catch
                {
                }

                local = new IPAddress[localList.Count];
                int index = 0;
                foreach (IPAddress ipAddress in localList)
                {
                    local[index] = ipAddress;
                    index++;
                }
                _LocalAddresses = local;

                return local;
            }
        }
    }
        #endif // !FEATURE_PAL

    private static object LocalAddressesLock
    {
        get
        {
            if (_LocalAddressesLock == null)
            {
                Interlocked.CompareExchange(ref _LocalAddressesLock, new object(), null);
            }
            return _LocalAddressesLock;
        }
    }
}

    // This is only for internal code path i.e. TLS stream.
    // See comments on GetNextBuffer() method below.
    //
    internal class SplitWritesState
    {
        private const int c_SplitEncryptedBuffersSize = 64*1024;
        private BufferOffsetSize[] _UserBuffers;
        private int _Index;
        private int _LastBufferConsumed;
        private BufferOffsetSize[] _RealBuffers;

        //
        internal SplitWritesState(BufferOffsetSize[] buffers)
        {
            _UserBuffers    = buffers;
            _LastBufferConsumed = 0;
            _Index          = 0;
            _RealBuffers = null;
        }
        //
        // Everything was handled
        //
        internal bool IsDone {
            get {
                if (_LastBufferConsumed != 0)
                    return false;

                for (int index = _Index ;index < _UserBuffers.Length; ++index)
                    if (_UserBuffers[index].Size != 0)
                        return false;

                return true;
            }
        }
        // Encryption takes CPU and if the input is large (like 10 mb) then a delay may
        // be 30 sec or so. Hence split the ecnrypt and write operations in smaller chunks
        // up to c_SplitEncryptedBuffersSize total.
        // Note that upon return from here EncryptBuffers() may additonally split the input
        // into chunks each <= chkSecureChannel.MaxDataSize (~16k) yet it will complete them all as a single IO.
        //
        //  Returns null if done, returns the _buffers reference if everything is handled in one shot (also done)
        //
        //  Otheriwse returns subsequent BufferOffsetSize[] to encrypt and pass to base IO method
        //
        internal BufferOffsetSize[] GetNextBuffers()
        {
            int curIndex = _Index;
            int currentTotalSize = 0;
            int lastChunkSize = 0;

            int  firstBufferConsumed = _LastBufferConsumed;

            for ( ;_Index < _UserBuffers.Length; ++_Index)
            {
                lastChunkSize = _UserBuffers[_Index].Size-_LastBufferConsumed;

                currentTotalSize += lastChunkSize;

                if (currentTotalSize > c_SplitEncryptedBuffersSize)
                {
                    lastChunkSize -= (currentTotalSize - c_SplitEncryptedBuffersSize);
                    currentTotalSize = c_SplitEncryptedBuffersSize;
                    break;
                }

                lastChunkSize = 0;
                _LastBufferConsumed = 0;
            }

            // Are we done done?
            if (currentTotalSize == 0)
                return null;

            // Do all buffers fit the limit?
            if (firstBufferConsumed == 0 && curIndex == 0 && _Index == _UserBuffers.Length)
                return _UserBuffers;

            // We do have something to split and send out
            int buffersCount = lastChunkSize == 0? _Index-curIndex: _Index-curIndex+1;

            if (_RealBuffers == null || _RealBuffers.Length != buffersCount)
                _RealBuffers = new BufferOffsetSize[buffersCount];

            int j = 0;
            for (; curIndex < _Index; ++curIndex)
            {
                _RealBuffers[j++] = new BufferOffsetSize(_UserBuffers[curIndex].Buffer, _UserBuffers[curIndex].Offset + firstBufferConsumed, _UserBuffers[curIndex].Size-firstBufferConsumed, false);
                firstBufferConsumed = 0;
            }

            if (lastChunkSize != 0)
            {
                _RealBuffers[j] = new BufferOffsetSize(_UserBuffers[curIndex].Buffer, _UserBuffers[curIndex].Offset + _LastBufferConsumed, lastChunkSize, false);
                if ((_LastBufferConsumed += lastChunkSize) == _UserBuffers[_Index].Size)
                {
                    ++_Index;
                    _LastBufferConsumed = 0;
                }
            }

            return _RealBuffers;

        }
    }




}
