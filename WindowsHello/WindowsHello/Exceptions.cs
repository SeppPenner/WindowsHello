using System;
using System.Runtime.Serialization;

namespace WindowsHello
{
    [Serializable]
    public class WindowsHelloException : Exception
    {
        public virtual bool IsPresentable { get { return false; } }

        public WindowsHelloException() { }
        public WindowsHelloException(string message) : base(message) { }
        public WindowsHelloException(string message, Exception inner) : base(message, inner) { }
        protected WindowsHelloException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class AuthProviderException : WindowsHelloException
    {
        public AuthProviderException() { }
        public AuthProviderException(string message) : base(message) { }
        public AuthProviderException(string message, Exception inner) : base(message, inner) { }
        protected AuthProviderException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class AuthProviderUserCancelledException : AuthProviderException
    {
        public AuthProviderUserCancelledException() : this("Operation was canceled by user.") { }
        public AuthProviderUserCancelledException(string message) : base(message) { }
        public AuthProviderUserCancelledException(string message, Exception inner) : base(message, inner) { }
        protected AuthProviderUserCancelledException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class AuthProviderInvalidKeyException : AuthProviderException
    {
        public override bool IsPresentable { get { return true; } }

        public AuthProviderInvalidKeyException(string message) : base(message) { }
        public AuthProviderInvalidKeyException(string message, Exception inner) : base(message, inner) { }
        protected AuthProviderInvalidKeyException() { }
        protected AuthProviderInvalidKeyException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class AuthProviderIsUnavailableException : AuthProviderException
    {
        public AuthProviderIsUnavailableException() : this("Authentication provider is not available.") { }
        public AuthProviderIsUnavailableException(string message) : base(message) { }
        public AuthProviderIsUnavailableException(string message, Exception inner) : base(message, inner) { }
        protected AuthProviderIsUnavailableException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class EnviromentErrorException : WindowsHelloException
    {
        public EnviromentErrorException() { }
        public EnviromentErrorException(string message) : base(message) { }
        public EnviromentErrorException(string message, Exception inner) : base(message, inner) { }

        public EnviromentErrorException(string debugInfo, int errorCode) : this(debugInfo + "\nError code: " + errorCode.ToString("X"))
        {
            // TODO: Implement ExternalException logic
        }

        protected EnviromentErrorException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class AuthProviderSystemErrorException : EnviromentErrorException
    {
        public AuthProviderSystemErrorException() { }
        public AuthProviderSystemErrorException(string message, int errorCode) : base(message, errorCode) { }
        public AuthProviderSystemErrorException(string message) : base(message) { }
        public AuthProviderSystemErrorException(string message, Exception inner) : base(message, inner) { }
        protected AuthProviderSystemErrorException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

}